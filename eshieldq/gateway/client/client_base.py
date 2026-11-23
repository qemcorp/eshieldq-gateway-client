#!/usr/bin/python3


import logging
import math
import os
import ssl
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import Callable

import requests
import urllib3
from requests import Response, Session
from requests.adapters import HTTPAdapter
from requests.structures import CaseInsensitiveDict
from eshieldq.gateway.schemas.auth import (
    API_AUTH_V1_TOKEN,
    API_AUTH_V2,
    API_AUTH_V2_TOKEN,
    CHANGE_PASSWORD_DEADLINE_SECONDS,
    CREDENTIAL_NETWORK_MARGIN_SECONDS,
    INITIAL_USER_TIMEOUT_SECONDS,
    LOGIN_TIMEOUT_SECONDS,
)
from eshieldq.gateway.schemas.sys import API_SYS_V1, JobNumber, JobStatus, JobStatusEnum
from eshieldq.gateway.schemas.users import InitialUser

from eshieldq.gateway.client.cert_utils import CertUtils

ADDRESS = "localhost"
HTTP_PORT = 8080
HTTPS_PORT = 443
API_ROOT = "/api"


def merge_dicts(dict_first: dict, dict_second: dict):
    merged_dict = dict_first.copy()
    merged_dict.update(dict_second)
    return merged_dict


class InitialUserRequiredError(Exception):
    pass


class OTPError(Exception):
    pass


class InvalidLoginError(Exception):
    pass


class PasswordExpiredError(Exception):
    pass


class UserLockedError(Exception):
    pass


class PasswordChangeUnsettledError(Exception):
    """Earlier password changes got no answer and may still commit.

    ``retry_after`` is the seconds until the oldest of them can no longer commit.
    """

    def __init__(self, message: str, retry_after: int | None):
        super().__init__(message)
        self.retry_after = retry_after


class LoginRateLimitedError(ConnectionError):
    """The appliance refused the login for now (429); ``retry_after`` seconds."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class LoginRecoveryDeferredError(InvalidLoginError):
    """Settling an unanswered password change needs another login attempt, and
    spending it now could lock the account out. ``retry_after`` seconds (0: the
    next relogin() may try)."""

    def __init__(self, message: str, retry_after: int = 0):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass
class _PendingPassword:
    """A password sent to change-password with no answer for that request."""

    password: str
    sent_at: float
    #: After this the change can no longer commit: the appliance enforces the
    #: route's deadline, and this adds the network margin on top.
    settle_by: float


class SSLAdapter(HTTPAdapter):
    def __init__(self, ssl_context=None, **kwargs):
        self.ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return


#: Writes that are harmless to repeat: a second login just issues another token.
_REPLAY_SAFE_WRITES = frozenset({API_AUTH_V1_TOKEN, API_AUTH_V2_TOKEN})


def _replay_misreports(
    action: str, headers: dict | None, session_headers=None
) -> bool:
    """Would re-sending this request answer for the replay, not the original?

    POST and PATCH may apply twice. A DELETE and a conditional write apply once
    either way, but the replay's answer is about the state the original left
    behind: a DELETE that succeeded is answered 404 the second time, and an
    If-Match PUT is answered 412 because the original moved the revision.
    Either way the caller is told its change failed when it was made. An
    unconditional PUT answers the same twice, so it stays retryable, as do
    reads. A header set to None is one requests drops before sending.
    """
    if action in ("post", "patch", "delete"):
        return True
    if action != "put":
        return False
    # Case-insensitive, last spelling wins: how requests resolves a per-call
    # override (merged after the persistent headers) of a session header.
    effective = CaseInsensitiveDict(session_headers or {})
    for name, value in (headers or {}).items():
        effective[name] = value
    return effective.get("If-Match") is not None



def _write_may_have_landed(exc: Exception) -> bool:
    """A read timeout: the request was sent, so the server may have applied it.

    requests raises ReadTimeout while waiting for headers, and ConnectionError
    wrapping urllib3's ReadTimeoutError when the body stalls after them.
    """
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return True
    return isinstance(exc, requests.exceptions.ConnectionError) and any(
        isinstance(arg, urllib3.exceptions.ReadTimeoutError) for arg in exc.args
    )

def _gateway_hid_answer(resp: Response) -> bool:
    """A proxy's 502/504: the appliance may have checked, and refused, the
    credential behind it."""
    return resp.status_code in (HTTPStatus.BAD_GATEWAY, HTTPStatus.GATEWAY_TIMEOUT)


def _never_sent(exc: Exception) -> bool:
    """The request failed while connecting, so the appliance never saw it. A
    reset or close after sending is NOT this: the change may have committed."""
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return True
    stack: list[object] = [exc]
    seen: set[int] = set()
    while stack:
        cur = stack.pop()
        if not isinstance(cur, BaseException) or id(cur) in seen:
            continue
        seen.add(id(cur))
        if isinstance(cur, urllib3.exceptions.NewConnectionError):
            return True
        stack.extend([cur.__cause__, cur.__context__, getattr(cur, "reason", None), *cur.args])
    return False


def _refused_before_change(resp: Response) -> bool:
    """The change endpoint answered that nothing was changed: any 4xx, or the
    appliance's 503 for a hash it could not run or finish in time."""
    if HTTPStatus.BAD_REQUEST <= resp.status_code < HTTPStatus.INTERNAL_SERVER_ERROR:
        return True
    text = (resp.text or "").lower()
    return resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE and (
        "nothing was changed" in text or "hashing is busy" in text
    )


def _otp_refusal(resp: Response) -> bool:
    """A 401 that is about the one-time password, not the password."""
    return "invalid otp" in (resp.text or "").lower()


class HttpClient:

    def __init__(
        self,
        address=ADDRESS,
        port=HTTPS_PORT,
        use_https=True,
        username=None,
        password=None,
        access_token=None,
        https_root_cert_file=None,
        use_hostname_ssl=False,
        hostname=None,
        cert_verify=True,
        client_key_file: str | None = None,
        client_cert_file: str | None = None,
        max_retries: int = 0,
        auto_relogin: bool = True,
        log_level: int = logging.DEBUG,
        raise_on_login_error=True,
        auto_password_update=False,
        pw_change_handler: Callable[[str], str] | None = None,
        otp_handler: Callable[[str], str] | None = None,
        initial_user_handler: Callable[[], InitialUser] | None = None,
        wait_for_jobs: bool = True,
        timeout: int = 5,
        ssl_context=None,
    ):
        self.address = address
        self.port = port
        self.schema = None
        self.api_url = ""
        self.session = None
        self._carried_cookies = None
        self.kwargs: dict = {}
        self.max_retries = max_retries
        self.ssl_context = ssl_context

        self.auto_relogin = auto_relogin
        self.try_relogin = auto_relogin
        self.raise_on_login_error = raise_on_login_error
        self.otp_value: str | None = None
        #: Guards the one handler-driven retry in parse_login_failure.
        self._otp_retry_active = False

        self.access_token = access_token
        self.username = username
        self.password = password
        self.use_hostname_ssl = use_hostname_ssl
        self.hostname = hostname
        self.use_https = use_https
        self.wait_for_jobs = wait_for_jobs

        self.log_level = log_level
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(self.log_level)

        self.cert_verify = cert_verify
        self.root_cert_file = https_root_cert_file

        self.client_cert_file = client_cert_file
        self.client_key_file = client_key_file
        self.auto_password_update = auto_password_update
        self.pw_change_handler = pw_change_handler
        self.otp_handler = otp_handler
        self.initial_user_handler = initial_user_handler
        # Unanswered password changes, per account (see change_password): any
        # may be that account's password now. While one is pending, relogin()
        # recovers instead of simply logging in, and remembers per account what
        # was refused (password -> refused until; inf = for good) and when
        # its own logins failed, so it never re-spends attempts.
        self._pending: dict[str, list[_PendingPassword]] = {}
        self._refused: dict[str, dict[str, float]] = {}
        self._failures: dict[str, list[float]] = {}
        self._needs_otp: dict[str, bool] = {}
        self._deadline_gateway: bool | None = None
        #: The appliance's lockout policy, learned from get_auth_settings();
        #: None until then, which recovery treats as the strictest (1).
        self.lockout_threshold: int | None = None
        self.lockout_window_sec: int | None = None
        self._clock = time.monotonic

        if client_key_file and client_cert_file:
            self.enable_mutual_auth(
                client_key_file, client_cert_file, refresh_session=False
            )

        if self.use_https:
            self.api_url += "https://"
            if self.root_cert_file:
                self.enable_cert_verify(self.root_cert_file, refresh_session=False)
            else:
                if not self.cert_verify:
                    self.disable_cert_verify()
                else:
                    raise ValueError(
                        "Root cert not provided - required for HTTPS verification"
                    )
        else:
            self.api_url += "http://"

        self.api_url += self.address + ":" + str(self.port)
        self.api_url += API_ROOT
        self.logger.debug("Using API URL:" + self.api_url)

        self.timeout = timeout
        self.set_kwargs(timeout=self.timeout)

    def __del__(self):
        self.close_session()

    def close_session(self):
        if self.session:
            self.session.close()
            self.session = None

    def _refresh_transport(self):
        """Rebuild the connection pool, keeping the session's cookies.

        TLS settings are baked into the pool, so a verify change only takes
        effect on a new one -- but the v2 auth cookie lives on the session, and
        dropping it silently logs this client out.
        """
        if self.session is not None:
            self._carried_cookies = self.session.cookies
        self.close_session()

    def open_session(self) -> Session:
        if self.session:
            return self.session
        self.session = Session()
        assert self.session

        carried = getattr(self, "_carried_cookies", None)
        if carried is not None:
            self.session.cookies.update(carried)
            self._carried_cookies = None

        if self.use_hostname_ssl:
            from requests_toolbelt.adapters import host_header_ssl

            if self.hostname is None:
                # discover the hostname from the server's HTTPS certificate
                try:
                    self.hostname = CertUtils.get_server_subject_alt_name(
                        address=self.address
                    )
                except Exception:
                    pass
                if self.hostname is None:
                    if not self.kwargs["verify"]:
                        self.hostname = "unknown"
                    else:
                        raise ValueError("Failed to discover hostname from server cert")
                self.logger.debug("Using hostname: " + self.hostname)

            self.session.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
            self.set_hostname(self.hostname)
        if self.max_retries:
            from requests.adapters import HTTPAdapter, Retry

            retries = Retry(
                total=self.max_retries,
                backoff_factor=0.1,
                status_forcelist=[500, 502, 503, 504],
                # reads only: a write's replay is do_http's decision
                allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
                # urllib3 counts an SSL error as "other" and would retry a
                # trust failure below do_http's guard.
                other=0,
            )

            self.session.mount("https://", HTTPAdapter(max_retries=retries))

        if self.ssl_context:

            # mount adapter with custom SSL context
            adapter = SSLAdapter(ssl_context=self.ssl_context)
            self.session.mount("https://", adapter)

        return self.session

    def get_hostname(self) -> str | None:
        return self.hostname

    def set_hostname(self, hostname: str):
        self.hostname = hostname
        self.logger.debug("Using HTTP header Hostname: " + self.hostname)
        self.kwargs["headers"] = merge_dicts(
            self.kwargs.get("headers", {}), {"Host": self.hostname}
        )
        return True

    def enable_mutual_auth(
        self, client_key_file: str, client_cert_file: str, refresh_session: bool = True
    ):
        if os.path.isfile(client_key_file) and os.path.isfile(client_cert_file):
            self.client_key_file = client_key_file
            self.client_cert_file = client_cert_file
            self.logger.debug("Using Client Cert: " + self.client_cert_file)
            self.logger.debug("Using Client Key: " + self.client_key_file)
            self.kwargs["cert"] = (client_cert_file, client_key_file)

            if refresh_session:
                self.close_session()
                self.open_session()
        else:
            raise ValueError("Client cert/key not provided - required for mutual auth")

    def disable_mutual_auth(self):
        self.kwargs["cert"] = None

    def disable_cert_verify(self):
        # Warning, not debug: this gives up peer authentication.
        self.logger.warning(
            "Disabled HTTPS certificate verification for %s:%s", self.address, self.port
        )
        self.kwargs["verify"] = False
        # The pool carries the OLD verification settings, so without this the
        # change silently does not take effect on the next request.
        self._refresh_transport()

    def enable_cert_verify(
        self, root_cert_file: str | None = None, refresh_session: bool = False
    ):
        if root_cert_file is None:
            root_cert_file = self.root_cert_file

        if root_cert_file and os.path.isfile(root_cert_file):
            self.logger.debug(
                "Enabled HTTPs Certificate Verification using " + root_cert_file
            )
            self.kwargs["verify"] = root_cert_file
            # Unconditional, for the same reason as disable_cert_verify(): a pool
            # built while verification was OFF goes on not verifying, so enabling
            # it was a claim rather than a fact. refresh_session only decides
            # whether to reopen eagerly.
            self._refresh_transport()
            if refresh_session:
                self.open_session()
        else:
            raise ValueError(
                f"Root cert {root_cert_file} not provided - required for HTTPS verification"
            )

    def set_max_retries(self, max_retries: int = 5):
        self.max_retries = max_retries
        self.close_session()
        self.open_session()

    def route_timeout(self, seconds: float, connect: float | None = None):
        """The read timeout for a route the appliance may take `seconds` to
        answer, and never shorter than the timeout this client was given.
        With `connect`, a (connect, read) pair whose connect part is exactly
        that: how long the request may take to reach the appliance."""
        configured = self.timeout
        if configured is None:
            read = None  # no timeout at all already outlasts any budget
        elif isinstance(configured, tuple):
            read = None if configured[1] is None else max(configured[1], seconds)
            if connect is None:
                return (configured[0], read)
        else:
            read = max(configured, seconds)
        return read if connect is None else (connect, read)

    def set_kwargs(self, **kwargs):
        self.kwargs = merge_dicts(self.kwargs, kwargs) if self.kwargs else kwargs
        self.logger.debug("Requests Kwargs: " + repr(self.kwargs))

    @staticmethod
    def _unrewindable_body(kwargs) -> str | None:
        """Name a payload that cannot be sent twice, or None if replay is safe.

        A file object is consumed by the first attempt: `requests` reads it to
        EOF, and re-sending the same dict transmits a ZERO-BYTE part while every
        header still says it is a file upload. The server then rejects a
        perfectly good certificate as malformed -- a retry can therefore fail
        with `400 Invalid Certificate - PEM format expected` on a PEM that is
        byte-for-byte valid.

        Every one-shot form `requests` accepts has to be covered -- a form
        this misses is retried after consumption and recreates the same
        corruption:

        * `files` as a dict OR as a list of `(field, value)` tuples;
        * a value that is a bare file object, or a `(name, fileobj)` /
          `(name, fileobj, content_type)` / 4-tuple with headers;
        * `data` as a file object, or as a generator/iterator, which `requests`
          streams with chunked encoding and which is empty second time round.

        Bytes, strings and mappings are re-encodable, so they stay retryable.
        """
        for key in ("files", "data"):
            value = kwargs.get(key)
            if value is None:
                continue

            if HttpClient._is_one_shot(value):
                return key

            # dict -> its values; list/tuple of (field, value) pairs -> the values.
            if isinstance(value, dict):
                candidates = list(value.values())
            elif isinstance(value, (list, tuple)):
                candidates = [
                    pair[1] if isinstance(pair, (list, tuple)) and len(pair) >= 2
                    else pair
                    for pair in value
                ]
            else:
                continue

            for candidate in candidates:
                # requests accepts (name, fileobj[, content_type[, headers]]).
                parts = (
                    candidate
                    if isinstance(candidate, tuple)
                    else (candidate,)
                )
                for part in parts:
                    if HttpClient._is_one_shot(part):
                        return key
        return None

    @staticmethod
    def _is_one_shot(value) -> bool:
        """True if sending this consumes it, so a second send would differ."""
        if isinstance(value, (bytes, bytearray, str, memoryview)):
            return False
        if hasattr(value, "read"):
            return True
        # A generator/iterator is consumed by iteration. Mappings and sequences
        # are not: requests re-encodes those from scratch each time.
        if isinstance(value, (dict, list, tuple, set)):
            return False
        return hasattr(value, "__next__")

    # Backstop for a wrapper that stringifies the cause instead of chaining it.
    _CERT_VERIFY_MARKERS = (
        "certificate verify failed",
        "certificate_verify_failed",
        "self-signed certificate",
        "self signed certificate",
        "hostname mismatch",
        # urllib3's own hostname check, both renderings:
        # "doesn't match 'x'" and "doesn't match either of ...".
        "doesn't match",
    )

    @staticmethod
    def _cert_error_types() -> tuple:
        """Every exception class that means "the peer failed verification".

        urllib3 does the hostname check itself when assert_hostname is set (which
        HostHeaderSSLAdapter does for use_hostname_ssl), and ITS CertificateError
        is a plain ValueError -- not an ssl.CertificateError -- so a structural
        check on the ssl types alone misses a hostname mismatch and retries the
        credential POST against an unverified peer.
        """
        types: list[type] = [ssl.SSLCertVerificationError, ssl.CertificateError]
        try:
            from urllib3.util.ssl_match_hostname import (
                CertificateError as _Urllib3CertificateError,
            )

            types.append(_Urllib3CertificateError)
        except Exception:  # pragma: no cover - urllib3 moved it
            pass
        return tuple(types)

    @classmethod
    def is_cert_verify_failure(cls, exc: BaseException) -> bool:
        """True if this SSLError is the peer failing verification.

        Separates a trust failure, which must never be retried, from a transient
        TLS transport error, which may be. The requests/urllib3/ssl wrapping
        varies by version, so walk the whole chain rather than one shape.
        """
        seen: set[int] = set()
        stack: list[object] = [exc]
        while stack:
            cur = stack.pop()
            if not isinstance(cur, BaseException) or id(cur) in seen:
                continue
            seen.add(id(cur))
            if isinstance(cur, cls._cert_error_types()):
                return True
            stack.append(cur.__cause__)
            stack.append(cur.__context__)
            stack.append(getattr(cur, "reason", None))
            stack.extend(cur.args)

        # Text match only for transport exceptions, so an unrelated error that
        # merely mentions a certificate stays retryable.
        if not isinstance(exc, (requests.exceptions.ConnectionError, ssl.SSLError)):
            return False
        text = str(exc).lower()
        return any(marker in text for marker in cls._CERT_VERIFY_MARKERS)

    def do_http(self, action, endpoint, retries=3, **kwargs) -> Response:
        self.open_session()
        combined_kwargs = merge_dicts(self.kwargs, kwargs)
        # `headers` is merged rather than replaced: the persistent kwargs carry
        # `Host` (set_hostname), and a shallow update would drop it the moment
        # any call passed a header of its own -- the request would then reach
        # the wrong virtual host instead of failing visibly. Per-call entries
        # still win, which is what an override means.
        if "headers" in kwargs and "headers" in self.kwargs:
            combined_kwargs["headers"] = merge_dicts(
                self.kwargs["headers"], kwargs["headers"]
            )

        if action not in ["get", "post", "patch", "delete", "put"]:
            raise ValueError("Invalid action: " + action)

        exception = None
        # get the session attribute and run it with the combined args
        try:
            resp = getattr(self.session, action)(
                self.api_url + endpoint, **combined_kwargs
            )
        except Exception as e:
            # One handler: a trust failure also arrives wrapped as ProxyError.
            if self.is_cert_verify_failure(e):
                # Never retry an unverified peer: the body is often a credential POST.
                self.logger.error(
                    "TLS certificate verification failed for %s%s: %s",
                    self.api_url,
                    endpoint,
                    e,
                )
                raise
            self.logger.debug(f"Exception {e} - Reconnecting and retrying operation")
            exception = e

        if exception is not None:
            # combined_kwargs, not kwargs: a body can also arrive via
            # set_kwargs(files=...), and those persistent kwargs are what was
            # actually sent. Checking only the per-call ones would miss a consumed
            # handle supplied that way and replay it as an empty upload.
            unrewindable = self._unrewindable_body(combined_kwargs)
            if unrewindable:
                # Replaying would send an empty body and turn a transport error
                # into a bogus validation error from the server. Surface the real
                # exception instead; the caller can retry with fresh bytes.
                self.logger.warning(
                    f"Not retrying {action.upper()} {endpoint}: '{unrewindable}' "
                    f"carries a consumed stream that cannot be replayed "
                    f"({type(exception).__name__}: {exception})"
                )
                raise exception
            if (
                _replay_misreports(
                    action,
                    combined_kwargs.get("headers"),
                    getattr(self.session, "headers", None),
                )
                and _write_may_have_landed(exception)
                and endpoint not in _REPLAY_SAFE_WRITES
            ):
                # The server may have applied a timed-out write (urllib3 reports a TLS
                # handshake stall the same way, so that is not retried either).
                self.logger.warning(
                    f"Not retrying {action.upper()} {endpoint}: it was sent and the "
                    f"server may have acted on it ({type(exception).__name__}: {exception})"
                )
                raise exception
            if retries > 0:
                self.close_session()
                self.open_session()
                return self.do_http(action, endpoint, retries=retries - 1, **kwargs)
            else:
                raise exception

        if resp.status_code == HTTPStatus.UNAUTHORIZED and self.try_relogin:
            # auth Token expired - need to get a new auth token.
            # Disable relogin for the duration of this attempt to prevent
            # infinite recursion (the relogin()/retry calls re-enter do_http),
            # but ALWAYS restore it afterwards. Restoring only on a successful
            # retry (the previous behaviour) latched try_relogin to False
            # whenever a relogin-retry also returned 401, permanently breaking
            # this client's ability to re-authenticate on any later request.
            self.try_relogin = False
            try:
                if "auth" in endpoint and "token" in endpoint:
                    return self.parse_login_failure(resp)

                # get new auth token
                relogin_resp = self.relogin()
                if relogin_resp.status_code != HTTPStatus.OK:
                    self.logger.info("Relogin failed")
                    return relogin_resp
                unrewindable = self._unrewindable_body(combined_kwargs)
                if unrewindable:
                    # Same trap as the exception retry above: the body is spent,
                    # so the replay would upload nothing. Return the 401 as-is --
                    # an honest auth failure beats a fabricated 400.
                    self.logger.warning(
                        f"Re-authenticated but not replaying {action.upper()} "
                        f"{endpoint}: '{unrewindable}' carries a consumed stream"
                    )
                    return resp
                # retry the original request with the new token
                resp = self.do_http(action, endpoint, **kwargs)
            finally:
                self.try_relogin = self.auto_relogin

        return resp

    def http_get(self, endpoint, **kwargs) -> Response:
        return self.do_http("get", endpoint, **kwargs)

    def http_post(self, endpoint, **kwargs) -> Response:
        return self.do_http("post", endpoint, **kwargs)

    def http_put(self, endpoint, **kwargs) -> Response:
        return self.do_http("put", endpoint, **kwargs)

    def http_patch(self, endpoint, **kwargs) -> Response:
        return self.do_http("patch", endpoint, **kwargs)

    def http_delete(self, endpoint, **kwargs) -> Response:
        return self.do_http("delete", endpoint, **kwargs)

    def check_job_response(
        self, response: Response, timeout=10, ignore_job_failure=False
    ) -> bool:
        if response.status_code == HTTPStatus.ACCEPTED:
            job = JobNumber(**response.json())
            if not self.wait_for_jobs:
                print("Not waiting for jobs")
                return True

            status = self.wait_for_job_done(job, timeout)
            if status and status.status == JobStatusEnum.COMPLETED:
                return True
            else:
                if ignore_job_failure:
                    print("Ignore job failure")
                    return True
                else:
                    if status is None:
                        print(
                            f"{self.address} Job {job.id} failed reading status -  ({job.descritpion}) - {response.text} "
                        )
                    return False
        print(f"{self.address} Failed job response: " + response.text)
        return False

    def wait_for_job_done(self, job: JobNumber, timeout=10) -> JobStatus | None:
        start = time.time()
        status = None
        while time.time() - start < timeout:
            response = self.http_get(API_SYS_V1 + f"/job-status/{job.id}")
            if response and response.status_code == HTTPStatus.OK:
                status = JobStatus(**response.json())
                if status.status != JobStatusEnum.RUNNING:
                    print(
                        f"{self.address} Job {job.id} status: {status.status.value} - ({job.descritpion})"
                    )
                    return status
            # print(f"Job {job_number.id} status: {status}")
            time.sleep(0.1)

        return status

    #: Unanswered password changes kept for relogin() to try.
    MAX_PENDING_PASSWORDS = 2
    #: How long a change-password may take to reach the appliance; it is never
    #: retried, so this bounds when the appliance's deadline can start.
    CHANGE_PASSWORD_CONNECT_TIMEOUT_S = 5
    #: A candidate refused on a gateway with no deadline is retried after this.
    UNBOUNDED_RETRY_S = 300
    #: The first rest-app that enforces the password routes' deadlines.
    DEADLINE_REST_APP_VERSION = (4, 1, 104)

    def _gateway_enforces_deadlines(self) -> bool:
        """Whether this appliance's rest-app enforces the route deadlines, so
        an unanswered change can be settled by time. Unknown is no: a
        candidate is then kept until an answer or clear_pending_passwords()."""
        if self._deadline_gateway is not None:
            return self._deadline_gateway
        saved, self.try_relogin = self.try_relogin, False
        try:
            resp = self.http_get(API_SYS_V1 + "/version", retries=0)
            software = resp.json().get("software", []) if resp.status_code == 200 else []
        except Exception:
            return False
        finally:
            self.try_relogin = saved
        for component in software:
            if component.get("name") == "eshieldq-gateway-rest-app":
                digits = []
                for part in str(component.get("version", "")).split(".")[:3]:
                    num = "".join(ch for ch in part if ch.isdigit())
                    digits.append(int(num) if num else 0)
                self._deadline_gateway = tuple(digits) >= self.DEADLINE_REST_APP_VERSION
                return self._deadline_gateway
        return False

    def clear_pending_passwords(self, username: str | None = None) -> None:
        """Forget this account's unanswered password changes: the caller has
        established the password some other way."""
        username = username or self.username or ""
        self._pending.pop(username, None)
        self._refused.pop(username, None)
        self._needs_otp.pop(username, None)

    # Must exceed the appliance's 60 s lock-acquire timeout: if the gateway is
    # wedged it answers 503 at ~60 s, and a client that gave up at 10 s replaced
    # that diagnosis with a timeout of its own -- then (before the guard above)
    # replayed the request with an empty body. Wait long enough to be told.
    UPLOAD_TIMEOUT_S = 90

    def upload_file(
        self, endpoint: str, file_name: str, timeout=None, data: dict | None = None
    ) -> Response:
        """Upload a file as bytes, so the request is replay-safe by construction.

        Reading the file here rather than handing `requests` an open handle is
        what makes a retry send the same payload; a file object would be at EOF
        by the second attempt. Certificates and keys are a few KB, so holding the
        contents in memory costs nothing. `data` is sent as form fields beside
        the file.
        """
        with open(file_name, "rb") as fd:
            contents = fd.read()
        files = {"file": (os.path.basename(file_name), contents)}

        resp = self.http_post(
            endpoint,
            files=files,
            data=data,
            timeout=self.UPLOAD_TIMEOUT_S if timeout is None else timeout,
        )
        return resp

    def parse_login_failure(self, resp) -> Response:
        """Handle login failures. Based on the response status code and text
        call handler functions that have been provided or raise exception."""

        exception: Exception | None = None

        # parse the response status code and text to determine the cause of the failure
        if resp.status_code == HTTPStatus.UNAUTHORIZED:
            if "invalid otp" in resp.text.lower():
                # get OTP and retry login
                if (
                    self.otp_handler
                    and self.username
                    and self.password
                    and not self._otp_retry_active
                ):
                    # Exactly one retry per login attempt. login() calls back
                    # into here on failure, so without the guard a gateway that
                    # keeps answering "invalid otp" recurses login ->
                    # parse_login_failure -> login until the interpreter's stack
                    # limit, minting a code per frame.
                    self._otp_retry_active = True
                    try:
                        self.otp_value = self.otp_handler(self.username)
                        return self.login(
                            self.username, self.password, otp=self.otp_value
                        )
                    finally:
                        self._otp_retry_active = False
                else:
                    exception = OTPError("One Time Password Incorrect")
            else:
                exception = InvalidLoginError("Invalid Login")
        elif resp.status_code == HTTPStatus.LOCKED and "Password Expired" in resp.text:
            if self.auto_password_update:
                # change password and try again
                return self.change_password()
            else:
                exception = PasswordExpiredError("Password Expired")

        elif resp.status_code == HTTPStatus.LOCKED:
            exception = UserLockedError("User is Locked")
        elif resp.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            headers = getattr(resp, "headers", None) or {}
            retry_after = headers.get("Retry-After")
            exception = LoginRateLimitedError(
                f"Too many authentication attempts; retry after {retry_after} s",
                retry_after=int(retry_after) if str(retry_after).isdigit() else None,
            )
        elif resp.status_code == HTTPStatus.FORBIDDEN and "No users exist" in resp.text:
            if self.initial_user_handler is not None:
                self.logger.debug("Calling Initial User Handler")
                initial_user = self.initial_user_handler()
                return self.initial_user_add(
                    username=initial_user.username,
                    password=initial_user.password,
                    instance_id=initial_user.instance_id,
                )
            else:
                exception = InitialUserRequiredError("Initial User Required")

        else:
            self.logger.debug("General Login Failure: " + repr(resp.status_code))
            exception = ConnectionError(
                "Failed with status code: " + repr(resp.status_code)
            )

        if self.raise_on_login_error and exception is not None:
            raise exception
        else:
            return resp

    def get_connection_details(self):
        # get the current Session and return the SSL connection details
        assert self.session
        with self.session.get(
            self.api_url + "api/users/v1/me", stream=True, **self.kwargs
        ) as response:
            if (
                response.raw._connection is None
                or response.raw._connection.sock is None
            ):
                raise Exception("No SSL Socket")
            sock = response.raw._connection.sock
            cipher = sock.cipher()  # type: ignore
            # peer_cert = sock.getpeercert()  # type: ignore
            # shared_ciphers = sock.shared_ciphers()  # type: ignore
        return cipher

    # --- unanswered password changes -----------------------------------------

    @property
    def pending_passwords(self) -> list[str]:
        """This account's unanswered password changes, oldest first."""
        return [entry.password for entry in self._pending.get(self.username or "", [])]

    def _settled(self, username: str, as_of: float, keep_failures: bool = False) -> None:
        """A login or change BEGUN at `as_of` verified the account's password.

        Every change whose deadline had passed by then cannot have committed
        unseen, so it is settled; one that could still commit stays. Recovery
        memory goes with the last of them.
        """
        entries = [e for e in self._pending.get(username, []) if e.settle_by > as_of]
        if entries:
            self._pending[username] = entries
            return
        self._pending.pop(username, None)
        self._refused.pop(username, None)
        if not keep_failures:  # only a login the appliance accepted clears them
            self._failures.pop(username, None)
        self._needs_otp.pop(username, None)  # a fresh episode asks the server

    def _note_failure(self, username: str) -> None:
        self._failures.setdefault(username, []).append(self._clock())

    def change_password(
        self, new_password: str | None = None, relogin: bool = True
    ) -> Response:
        assert self.username and self.password
        from eshieldq.gateway.client.client_auth import ClientAuthMgr
        from eshieldq.gateway.client.client_users import gen_rand_pw
        from eshieldq.gateway.schemas.users import UserPassword

        if new_password is None:
            if self.pw_change_handler is not None:
                self.logger.debug(
                    "Calling Password Change Handler for user " + self.username
                )
                new_password = self.pw_change_handler(self.username)
            else:
                new_password = gen_rand_pw()
                self.logger.debug(f"Generated New Password for user {self.username}")

        UserPassword(password=new_password)  # refused locally: nothing is sent
        username = self.username
        enforced = self._gateway_enforces_deadlines()  # before the clock starts
        started = self._clock()
        # Two-phase. The candidate is recorded BEFORE the request, because a
        # request that gets no answer may still commit: the client cannot replay
        # the POST, and keeping only the old password would leave it holding a
        # credential the appliance no longer accepts. `password` moves only on
        # a 200. A candidate stays pending until the appliance answers for its
        # request or the route's enforced deadline has passed.
        # The appliance stops the request at its deadline, counted from when the
        # request reaches it: at most the connect budget after `started`. On a
        # gateway that does not enforce deadlines nothing settles by time.
        settle_by = (
            started
            + self.CHANGE_PASSWORD_CONNECT_TIMEOUT_S
            + CHANGE_PASSWORD_DEADLINE_SECONDS
            + CREDENTIAL_NETWORK_MARGIN_SECONDS
            if enforced
            else math.inf
        )
        entries = self._pending.setdefault(username, [])
        entry = next((e for e in entries if e.password == new_password), None)
        added = entry is None
        if added:
            unexpired = [e for e in entries if started < e.settle_by]
            if len(unexpired) >= self.MAX_PENDING_PASSWORDS:
                soonest = min(e.settle_by for e in unexpired)
                if soonest == math.inf:
                    raise PasswordChangeUnsettledError(
                        f"{len(unexpired)} password changes for {username} got no "
                        "answer, and this gateway does not bound when they can "
                        "commit; relogin() or clear_pending_passwords() first",
                        retry_after=None,
                    )
                wait = math.ceil(soonest - started)
                raise PasswordChangeUnsettledError(
                    f"{len(unexpired)} password changes for {username} got no "
                    f"answer and may still commit; retry in {wait} s",
                    retry_after=wait,
                )
            entry = _PendingPassword(new_password, started, 0.0)
            entries.append(entry)
        # Sent again: this request can commit until ITS deadline, and a refusal
        # seen before it proves nothing about it.
        entry.sent_at = started
        entry.settle_by = settle_by
        self._refused.get(username, {}).pop(new_password, None)
        # A 401 here is the change endpoint refusing the OLD password, not an
        # expired session, so it is answered rather than relogged-in and replayed.
        saved, self.try_relogin = self.try_relogin, False
        try:
            resp = ClientAuthMgr(self).user_change_password(
                username=username,
                old_password=self.password,
                new_password=new_password,
            )
        except Exception as exc:
            if _never_sent(exc):
                if added:
                    # It could not connect, so it was never sent: nothing can commit.
                    self._pending[username] = [e for e in entries if e is not entry]
            else:
                # It may have reached the appliance and been refused.
                self._note_failure(username)
            raise
        finally:
            self.try_relogin = saved
        if resp.status_code == HTTPStatus.OK:
            self.password = new_password
            self._pending[username] = [e for e in entries if e is not entry]
            # The old password verified for a request begun at `started`.
            self._settled(username, started)
            if relogin:
                return self.relogin()
            else:
                return resp
        if resp.status_code == HTTPStatus.UNAUTHORIZED or _gateway_hid_answer(resp):
            # The old password was refused, or a proxy hid whether it was.
            self._note_failure(username)
        if added and _refused_before_change(resp):
            # The appliance answered for this request: it changed nothing. That
            # says nothing about any earlier one, which stays pending.
            self._pending[username] = [e for e in entries if e is not entry]
            if not self._pending[username] and not self._refused.get(username):
                self._pending.pop(username, None)
        self.logger.debug("Failed Changing Password: " + repr(resp.status_code))
        return self.parse_login_failure(resp)

    def relogin(
        self,
    ) -> Response:
        if self.username is None or self.password is None:
            raise Exception("Cannot relogin with no username or password")
        # NEVER the cached `otp_value`. A code is single-use: the appliance
        # records the TOTP step it belonged to and refuses that step and every
        # earlier one afterwards (RFC 6238 section 5.2), so a cached code has
        # either been spent already or was never valid. Re-presenting it made
        # every automatic relogin fail by construction -- which is what happens
        # after any operation that revokes the caller's own session.
        #
        # A fresh code is not minted here either. Whether this account even has
        # a second factor is the SERVER's answer, not something to guess at:
        # logging in without one and letting `parse_login_failure` mint from
        # `otp_handler` on "invalid otp" asks exactly once, only when a code is
        # actually required. Minting up front instead prompts the console CLI
        # user -- it installs a prompting handler for every account -- on a
        # relogin for an account with no factor at all.
        #
        # Recovering while a change is unanswered, and until a login succeeds
        # after one: what was refused on the way is not sent again.
        if self._pending.get(self.username) or self._refused.get(self.username):
            return self._recover_login()
        return self.login(self.username, self.password, otp=None)

    def _failures_left(self, username: str, now: float) -> int | None:
        """Failed logins recovery may still cause before the lockout: None for
        no limit. Unknown, the threshold is taken as 1."""
        threshold = self.lockout_threshold
        if threshold == 0:
            return None  # the limiter is off
        if threshold is None or threshold == 1:
            # One attempt per call: a lone failure locks the account whatever
            # is done, so the likeliest credential is all that is tried.
            return 1
        window = self.lockout_window_sec or 900
        recent = [t for t in self._failures.get(username, []) if t > now - window]
        self._failures[username] = recent
        return threshold - 1 - len(recent)

    def _out_of_attempts(self, username: str, now: float) -> LoginRecoveryDeferredError:
        window = self.lockout_window_sec or 900
        recent = self._failures.get(username) or [now]
        wait = max(0, math.ceil(recent[0] + window - now))
        return LoginRecoveryDeferredError(
            f"settling {username}'s unanswered password change would risk the "
            f"login lockout; retry in {wait} s",
            retry_after=wait,
        )

    def _recover_login(self) -> Response:
        """Log in while password changes for this account are unanswered.

        Tries the newest viable candidate first, then older ones, then the held
        password -- skipping what this account already refused -- and never
        exceeds the appliance's login attempt limit. Progress is kept across
        calls. A refusal settles a candidate only from a probe begun after its
        deadline; before that it is retried once the deadline passes.
        """
        username = self.username
        assert username is not None and self.password is not None
        now = self._clock()
        refused = self._refused.setdefault(username, {})
        entries = self._pending.get(username, [])
        order = [e.password for e in reversed(entries)]  # newest first
        if self.password not in order:
            order.append(self.password)
        viable = [p for p in order if refused.get(p, 0.0) <= now]
        # Untried credentials before a retry of one refused earlier, so a
        # candidate retried on a timer can never starve one not yet tried.
        viable.sort(key=lambda p: p in refused)
        if not viable:
            pending_until = [t for t in refused.values() if t != math.inf]
            if pending_until:
                wait = math.ceil(min(pending_until) - now)
                raise LoginRecoveryDeferredError(
                    f"every password for {username} was refused; a change may "
                    f"still commit, retry in {wait} s",
                    retry_after=wait,
                )
            raise InvalidLoginError(f"every known password for {username} was refused")

        left = self._failures_left(username, now)
        if left is not None and left <= 0:
            raise self._out_of_attempts(username, now)
        for password in viable:
            started = self._clock()
            code = None
            if self._needs_otp.get(username) and self.otp_handler is not None:
                code = self.otp_handler(username)
            probe = self._token_probe(username, password, code)
            if _otp_refusal(probe) and code is None and self.otp_handler is not None:
                # The password verified and a factor is due.
                self._needs_otp[username] = True
                self._note_failure(username)
                left = None if left is None else left - 1
                if left is not None and left <= 0:
                    raise self._out_of_attempts(username, self._clock())
                probe = self._token_probe(username, password, self.otp_handler(username))
            expired = (
                probe.status_code == HTTPStatus.LOCKED
                and "Password Expired" in probe.text
            )
            if probe.status_code == HTTPStatus.OK or expired:
                if password != self.password:
                    self.logger.info(
                        f"A password change for {username} that got no answer "
                        "had been committed; using the new password"
                    )
                self.password = password
                self._pending[username] = [e for e in entries if e.password != password]
                refused.clear()
                self._settled(username, started, keep_failures=expired)
                if expired:
                    self._note_failure(username)
                if not expired:
                    self._failures.pop(username, None)
                    return self._complete_login(probe)
                # Answer the 423 itself: logging in again would spend a factor
                # code a second time within its step.
                return self.parse_login_failure(probe)
            if probe.status_code != HTTPStatus.UNAUTHORIZED:
                # 429 or a 5xx says nothing about the password: stop, report it.
                if _gateway_hid_answer(probe):
                    self._note_failure(username)
                return self.parse_login_failure(probe)
            self._note_failure(username)
            if _otp_refusal(probe):
                # The password verified; its factor did not.
                if self.raise_on_login_error:
                    raise OTPError("One Time Password Incorrect")
                return probe
            entry = next((e for e in entries if e.password == password), None)
            if entry is not None and entry.settle_by == math.inf:
                # No known deadline: it may commit at any time, so it is tried
                # again later rather than given up -- after the others.
                refused[password] = self._clock() + self.UNBOUNDED_RETRY_S
            elif entry is not None and started < entry.settle_by:
                refused[password] = entry.settle_by  # may still commit
            else:
                refused[password] = math.inf
                if entry is not None:
                    entries.remove(entry)
            left = None if left is None else left - 1
            if left is not None and left <= 0:
                break
        raise LoginRecoveryDeferredError(
            f"{username}'s password was refused; relogin() again to try the "
            "next candidate"
        )

    def _token_probe(self, username: str, password: str, code: str | None) -> Response:
        """Exactly one token request: no relogin, no rotation, no transport
        replay -- each could be another counted attempt. One that got no answer
        is counted as a failure, since it may have been one."""
        saved, self.try_relogin = self.try_relogin, False
        try:
            return self.auth_token(
                username=username, password=password, client_secret=code, retries=0
            )
        except Exception as exc:
            if not _never_sent(exc):
                self._note_failure(username)
            raise
        finally:
            self.try_relogin = saved

    def logout(
        self,
    ) -> Response | None:
        try:
            resp = self.http_post(API_AUTH_V2 + "/logout")
            if self.session:
                for cookie in self.session.cookies:
                    if cookie.name == "access_token":
                        self.session.cookies.clear(
                            domain=cookie.domain, path=cookie.path, name=cookie.name
                        )
            return resp
        except Exception as e:
            self.logger.debug(f"Logout Exception: {e}")
            return None

    def login(
        self,
        username: str,
        password: str,
        otp: str | None = None,
        update_user: bool = False,
    ) -> Response:
        self.otp_value = otp
        started = self._clock()
        resp = self.auth_token(
            username=username, password=password, client_secret=self.otp_value
        )
        verified = resp.status_code == HTTPStatus.OK or (
            resp.status_code == HTTPStatus.LOCKED and "Password Expired" in resp.text
        )
        held = (username, password) == (self.username, self.password)
        if verified and (held or update_user):
            # This account's password verified for a login begun at `started`:
            # changes past their deadline by then did not commit.
            self._settled(username, started)
        elif resp.status_code == HTTPStatus.UNAUTHORIZED and username == self.username:
            self._note_failure(username)
        if resp.status_code == HTTPStatus.OK:
            if update_user:
                self.username = username
                self.password = password
            if (username, password) == (self.username, self.password):
                self._refused.pop(username, None)
                self._failures.pop(username, None)
            return self._complete_login(resp)
        self.logger.debug("Failed Login: " + repr(resp.status_code))
        return self.parse_login_failure(resp)

    def _complete_login(self, resp: Response) -> Response:
        """Adopt the session a 200 from the token endpoint carries."""
        kwargs: dict = {}
        # check for v1/auth response or v2/auth response
        # first check that a cookie is present in the response
        if "access_token" not in resp.cookies:
            # v1: a bearer token in the body. (v2 sets an HTTP cookie, which the
            # session has already stored.)
            try:
                json_data = resp.json()
            except Exception:
                json_data = {}
            if isinstance(json_data, dict) and "access_token" in json_data:
                self.access_token = json_data["access_token"]
                kwargs = {"headers": {"Authorization": f"Bearer {self.access_token}"}}
        # add the headers to future sessions
        self.set_kwargs(**kwargs)
        # The code has now been spent. Keeping it would only let a later
        # relogin re-present a value the appliance is guaranteed to refuse,
        # so drop it and make the next login source a fresh one.
        self.otp_value = None
        return resp

    def initial_user_add_v1(
        self,
        username: str,
        password: str,
    ) -> Response:
        from eshieldq.gateway.schemas.users import API_USERS_V1, UserCreate

        user_register = UserCreate(
            username=username, password=password, is_admin=True
        ).model_dump()

        try:
            resp = self.http_post(
                API_USERS_V1 + "/initial",
                json=user_register,
                timeout=self.route_timeout(INITIAL_USER_TIMEOUT_SECONDS),
            )
        except Exception as exc:
            return self._initial_user_unanswered(exc, username, password)
        if resp.status_code == HTTPStatus.CREATED:
            # store the username/password
            self.username = username
            self.password = password
            return self.login(username=self.username, password=self.password)
        else:
            self.logger.debug("Failed adding initial user: " + repr(resp.status_code))
            return self.parse_login_failure(resp)

    def initial_user_add_v2(
        self, username: str, password: str, instance_id: str
    ) -> Response:
        from eshieldq.gateway.schemas.users import API_USERS_V2, InitialUser

        user_register = InitialUser(
            username=username, password=password, is_admin=True, instance_id=instance_id
        ).model_dump()

        try:
            resp = self.http_post(
                API_USERS_V2 + "/initial",
                json=user_register,
                timeout=self.route_timeout(INITIAL_USER_TIMEOUT_SECONDS),
            )
        except Exception as exc:
            return self._initial_user_unanswered(exc, username, password)
        if resp.status_code == HTTPStatus.CREATED:
            # store the username/password
            self.username = username
            self.password = password
            return self.login(username=self.username, password=self.password)
        else:
            self.logger.debug("Failed adding initial user: " + repr(resp.status_code))
            return self.parse_login_failure(resp)

    def _initial_user_unanswered(
        self, exc: Exception, username: str, password: str
    ) -> Response:
        """The bootstrap got no answer and may have created the account: the
        appliance enforces the route's deadline, so by now it has either
        committed or not. A login with the same credentials settles which."""
        if not _write_may_have_landed(exc):
            raise exc
        saved, self.try_relogin = self.try_relogin, False
        try:
            probe = self.auth_token(username=username, password=password)
        finally:
            self.try_relogin = saved
        if probe.status_code != HTTPStatus.OK:
            raise exc
        self.logger.info(f"The initial user {username} had been created; logged in")
        self.username = username
        self.password = password
        return self._complete_login(probe)

    def initial_user_add(
        self, username: str, password: str, instance_id: str
    ) -> Response:
        # @better support fallback to v1 initial user if v2 is not supported
        return self.initial_user_add_v2(
            username=username, password=password, instance_id=instance_id
        )

    def auth_token(
        self,
        username: str,
        password: str,
        scope: str | None = "",
        client_id: str | None = None,
        client_secret: str | None = None,
        retries: int = 3,
    ) -> Response:
        login = {
            "username": username,
            "password": password,
            "scope": scope,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        timeout = self.route_timeout(LOGIN_TIMEOUT_SECONDS)
        resp = self.http_post(
            API_AUTH_V2_TOKEN, data=login, timeout=timeout, retries=retries
        )
        if resp.status_code == HTTPStatus.NOT_FOUND:
            return self.http_post(
                API_AUTH_V1_TOKEN, data=login, timeout=timeout, retries=retries
            )
        return resp
