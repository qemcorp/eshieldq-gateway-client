#!/usr/bin/python3


import logging
import os
import ssl
import time
from http import HTTPStatus
from typing import Callable

import requests
from requests import Response, Session
from requests.adapters import HTTPAdapter
from eshieldq.gateway.schemas.auth import API_AUTH_V2
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

    # Must exceed the appliance's 60 s lock-acquire timeout: if the gateway is
    # wedged it answers 503 at ~60 s, and a client that gave up at 10 s replaced
    # that diagnosis with a timeout of its own -- then (before the guard above)
    # replayed the request with an empty body. Wait long enough to be told.
    UPLOAD_TIMEOUT_S = 90

    def upload_file(self, endpoint: str, file_name: str, timeout=None) -> Response:
        """Upload a file as bytes, so the request is replay-safe by construction.

        Reading the file here rather than handing `requests` an open handle is
        what makes a retry send the same payload; a file object would be at EOF
        by the second attempt. Certificates and keys are a few KB, so holding the
        contents in memory costs nothing.
        """
        with open(file_name, "rb") as fd:
            contents = fd.read()
        files = {"file": (os.path.basename(file_name), contents)}

        resp = self.http_post(
            endpoint,
            files=files,
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
                if self.otp_handler and self.username and self.password:
                    self.otp_value = self.otp_handler(self.username)
                    resp = self.login(self.username, self.password, otp=self.otp_value)
                    return resp
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

    def change_password(
        self, new_password: str | None = None, relogin: bool = True
    ) -> Response:
        assert self.username and self.password
        from eshieldq.gateway.client.client_auth import ClientAuthMgr
        from eshieldq.gateway.client.client_users import gen_rand_pw

        if new_password is None:
            if self.pw_change_handler is not None:
                self.logger.debug(
                    "Calling Password Change Handler for user " + self.username
                )
                new_password = self.pw_change_handler(self.username)
            else:
                new_password = gen_rand_pw()
                self.logger.debug(f"Generated New Password for user {self.username}")

        resp = ClientAuthMgr(self).user_change_password(
            username=self.username,
            old_password=self.password,
            new_password=new_password,
        )
        if resp.status_code == HTTPStatus.OK:
            self.password = new_password
            if relogin:
                return self.relogin()
            else:
                return resp
        else:
            self.logger.debug("Failed Changing Password: " + repr(resp.status_code))
            return self.parse_login_failure(resp)

    def relogin(
        self,
    ) -> Response:
        if self.username is None or self.password is None:
            raise Exception("Cannot relogin with no username or password")
        return self.login(self.username, self.password, otp=self.otp_value)

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
        resp = self.auth_token(
            username=username, password=password, client_secret=self.otp_value
        )
        if resp.status_code == HTTPStatus.OK:
            # check for v1/auth response or v2/auth response
            # first check that a cookie is present in the response
            if "access_token" in resp.cookies:
                # v2 response - HTTP cookie based auth - session already updates cookies!
                # if self.session:
                #     self.session.cookies.update(resp.cookies)
                # check that access_token cookie is present
                # new_cookie = resp.cookies["access_token"]
                # assert new_cookie

                kwargs = {}
            else:
                has_json = False
                try:
                    json_data = resp.json()
                    has_json = isinstance(json_data, dict)
                except Exception:
                    json_data = {}
                if has_json and "access_token" in json_data:
                    self.access_token = json_data["access_token"]
                    kwargs = {
                        "headers": {"Authorization": f"Bearer {self.access_token}"}
                    }

            if update_user:
                self.username = username
                self.password = password
            # add the headers to future sessions
            self.set_kwargs(**kwargs)
            return resp
        else:
            self.logger.debug("Failed Login: " + repr(resp.status_code))
            return self.parse_login_failure(resp)

    def initial_user_add_v1(
        self,
        username: str,
        password: str,
    ) -> Response:
        from eshieldq.gateway.schemas.users import API_USERS_V1, UserCreate

        user_register = UserCreate(
            username=username, password=password, is_admin=True
        ).model_dump()

        resp = self.http_post(API_USERS_V1 + "/initial", json=user_register)
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

        resp = self.http_post(API_USERS_V2 + "/initial", json=user_register)
        if resp.status_code == HTTPStatus.CREATED:
            # store the username/password
            self.username = username
            self.password = password
            return self.login(username=self.username, password=self.password)
        else:
            self.logger.debug("Failed adding initial user: " + repr(resp.status_code))
            return self.parse_login_failure(resp)

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
    ) -> Response:
        login = {
            "username": username,
            "password": password,
            "scope": scope,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        from eshieldq.gateway.schemas.auth import API_AUTH_V2_TOKEN

        resp = self.http_post(API_AUTH_V2_TOKEN, data=login)
        if resp.status_code == HTTPStatus.NOT_FOUND:
            from eshieldq.gateway.schemas.auth import API_AUTH_V1_TOKEN

            return self.http_post(API_AUTH_V1_TOKEN, data=login)
        return resp
