#!/usr/bin/python3


from contextlib import contextmanager
from http import HTTPStatus

from requests import Response
from eshieldq.gateway.schemas.auth import (
    API_AUTH_V1,
    API_AUTH_V2,
    CHANGE_PASSWORD_TIMEOUT_SECONDS,
    LOGIN_TIMEOUT_SECONDS,
    OtpEnrollModel,
    SysSecuritySettings,
)

from .client_base import HttpClient


class ClientAuthMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    @contextmanager
    def _no_relogin(self):
        """Suppress the automatic re-login for one call.

        A 401 from the step-up routes means the SUPPLIED password or one-time
        password was wrong, not that the session expired. Left to itself the
        client would try to re-authenticate with its cached OTP -- a code that
        is by then a step or more old -- and surface the result as an OTPError
        from a call that never had anything to do with logging in.
        """
        # Establish the session FIRST, while the automatic re-login is still
        # available: these wrappers are often the first call a fresh client
        # makes, and suppressing re-login before authenticating once would turn
        # "not logged in yet" into a bare 401 from the endpoint.
        session = getattr(self.http_client, "session", None)
        if session is None or "access_token" not in session.cookies:
            self.http_client.relogin()

        previous = self.http_client.try_relogin
        self.http_client.try_relogin = False
        try:
            yield
        finally:
            self.http_client.try_relogin = previous

    def _step_up_timeout(self):
        """The step-up routes re-verify the password through the login path."""
        return self.http_client.route_timeout(LOGIN_TIMEOUT_SECONDS)

    def user_login(self, username="user", password="string", otp_value=None):
        login = {
            "username": username,
            "password": password,
            "scope": "",
            "client_id": None,
            "client_secret": otp_value,
        }
        # v2 first (cookie based); v1 only on a 404, never on an exception.
        timeout = self.http_client.route_timeout(LOGIN_TIMEOUT_SECONDS)
        resp = self.http_client.http_post(
            API_AUTH_V2 + "/token", data=login, timeout=timeout
        )
        if resp.status_code == HTTPStatus.NOT_FOUND:
            return self.http_client.http_post(
                API_AUTH_V1 + "/token", data=login, timeout=timeout
            )
        return resp

    def user_change_password(
        self,
        username="user",
        old_password="string",
        otp_value=None,
        new_password="string",
    ):
        from eshieldq.gateway.schemas.users import UserChangePassword, UserPassword

        login = UserChangePassword(
            username=username,
            password=old_password,
            scope="",
            client_id=None,
            client_secret=otp_value,
            new_password=UserPassword(password=new_password),
        ).model_dump()

        # Never replayed on a timeout (it is not idempotent), so it waits as long
        # as the appliance may take: a client that gives up first reports a
        # failure for a change the appliance then commits.
        # A short connect budget and no transport retry: when the request
        # reaches the appliance is what an unanswered change is settled by.
        return self.http_client.http_post(
            API_AUTH_V1 + "/change-password",
            json=login,
            timeout=self.http_client.route_timeout(
                CHANGE_PASSWORD_TIMEOUT_SECONDS,
                connect=self.http_client.CHANGE_PASSWORD_CONNECT_TIMEOUT_S,
            ),
            retries=0,
        )

    def get_auth_settings(self) -> tuple[Response, SysSecuritySettings | None]:
        resp = self.http_client.http_get(API_AUTH_V1 + "/settings")
        if resp and resp.status_code == HTTPStatus.OK:
            settings = SysSecuritySettings(**resp.json())
            # What password-change recovery budgets its login attempts against.
            self.http_client.lockout_threshold = settings.login_lockout_threshold
            self.http_client.lockout_window_sec = settings.login_lockout_window_sec
            return resp, settings

        return resp, None

    def set_auth_settings(
        self,
        otp_enforce=False,
        token_timeout_sec=30 * 60,
        password_timeout_sec=86400 * 90,
        login_lockout_threshold=None,
        login_lockout_window_sec=None,
        login_lockout_duration_sec=None,
        otp_enrollment_requires_admin_token=None,
    ) -> Response:
        """Replace the security settings.

        The appliance rewrites the row wholesale, so every field is sent. The
        three lockout arguments therefore default to None meaning KEEP WHAT IS
        CONFIGURED, read back from the appliance first: every existing caller
        passes one field and lets the rest fall to defaults, so a default value
        here would have every `set_auth_settings(otp_enforce=True)` call
        quietly reset an operator's lockout policy.
        """
        # otp_enrollment_requires_admin_token joins the lockout arguments in
        # meaning KEEP WHAT IS CONFIGURED. It defaults to true in the schema,
        # so a positional default here would have every unrelated settings
        # write silently re-arm it and undo an operator's opt-out.
        lockout = (
            login_lockout_threshold,
            login_lockout_window_sec,
            login_lockout_duration_sec,
            otp_enrollment_requires_admin_token,
        )
        if any(value is None for value in lockout):
            # Read the policy to preserve it. If that read fails, RETURN the
            # failure: substituting schema defaults here would turn a transient
            # GET error during an unrelated settings update into a silent reset
            # of the operator's lockout policy.
            #
            # Known limitation, inherited from the endpoint: it replaces the row
            # wholesale with no concurrency control, so this read-then-write can
            # lose a policy change made in between. Preserving omitted fields
            # atomically needs server-side merge semantics, which is an API
            # change of its own.
            read, current = self.get_auth_settings()
            if current is None:
                return read
            if login_lockout_threshold is None:
                login_lockout_threshold = current.login_lockout_threshold
            if login_lockout_window_sec is None:
                login_lockout_window_sec = current.login_lockout_window_sec
            if login_lockout_duration_sec is None:
                login_lockout_duration_sec = current.login_lockout_duration_sec
            if otp_enrollment_requires_admin_token is None:
                otp_enrollment_requires_admin_token = (
                    current.otp_enrollment_requires_admin_token
                )

        data = SysSecuritySettings(
            otp_enforce=otp_enforce,
            token_timeout_sec=token_timeout_sec,
            password_timeout_sec=password_timeout_sec,
            login_lockout_threshold=login_lockout_threshold,
            login_lockout_window_sec=login_lockout_window_sec,
            login_lockout_duration_sec=login_lockout_duration_sec,
            otp_enrollment_requires_admin_token=otp_enrollment_requires_admin_token,
        ).model_dump()

        return self._post_settings(data)

    def _learn_lockout(self, settings: dict | None) -> None:
        """Recovery budgets its logins against this; a policy just written
        replaces what was read before it. Anything not known for certain --
        a value it cannot read as the appliance would, or a write whose outcome
        is unknown (settings None) -- forgets the whole policy."""

        def as_int(value):
            if isinstance(value, bool):
                raise ValueError(value)
            if isinstance(value, int):
                return value
            number = float(value)  # "3600.0" coerces like the appliance's model
            if not number.is_integer():
                raise ValueError(value)
            return int(number)

        try:
            threshold = as_int(settings["login_lockout_threshold"])
            window = as_int(settings["login_lockout_window_sec"])
        except (TypeError, ValueError, KeyError):
            threshold = window = None
        self.http_client.lockout_threshold = threshold
        self.http_client.lockout_window_sec = window

    def _post_settings(self, settings: dict) -> Response:
        try:
            resp = self.http_client.http_post(API_AUTH_V1 + "/settings", json=settings)
        except Exception:
            self._learn_lockout(None)  # it may have been applied
            raise
        if resp is not None and resp.status_code == HTTPStatus.OK:
            self._learn_lockout(settings)
        elif resp is None or resp.status_code in (
            HTTPStatus.BAD_GATEWAY,
            HTTPStatus.GATEWAY_TIMEOUT,
        ):
            self._learn_lockout(None)
        return resp

    def set_auth_settings_response(self, settings: dict) -> Response:
        """POST ``settings`` as given, without the client-side model check.

        For callers that need the appliance's own answer to a value the model
        would refuse locally (a 422 for an out-of-range field).
        """
        return self._post_settings(settings)

    def user_otp_enroll(
        self,
        password: str,
        otp_value: str | None = None,
        activation_code: str | None = None,
    ) -> tuple[Response, OtpEnrollModel | None]:
        """Begin enrolling a second factor.

        The returned model is the ONLY place the seed appears. Nothing reads it
        back afterwards, so a caller that needs it must keep it.
        """
        data = {
            "password": password,
            "otp_value": otp_value,
            "activation_code": activation_code,
        }
        with self._no_relogin():
            resp = self.http_client.http_post(
                API_AUTH_V1 + "/otp/enroll", json=data, timeout=self._step_up_timeout()
            )
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, OtpEnrollModel(**resp.json())
        return resp, None

    def user_otp_enable(
        self,
        password: str,
        enrollment_id: str,
        otp_code: str,
        otp_value: str | None = None,
        activation_code: str | None = None,
    ) -> Response:
        """Confirm a pending enrollment and activate it.

        ``otp_code`` comes from the PENDING seed and proves the authenticator
        was provisioned; ``otp_value`` is the current factor's code, needed
        only when one is already enrolled.
        """
        data = {
            "password": password,
            "otp_value": otp_value,
            "activation_code": activation_code,
            "enrollment_id": enrollment_id,
            "otp_code": otp_code,
        }
        with self._no_relogin():
            return self.http_client.http_post(
                API_AUTH_V1 + "/otp/enable", json=data, timeout=self._step_up_timeout()
            )

    def user_otp_disable(self, password: str, otp_value: str) -> Response:
        data = {"password": password, "otp_value": otp_value}
        with self._no_relogin():
            resp = self.http_client.http_post(
                API_AUTH_V1 + "/otp/disable", json=data, timeout=self._step_up_timeout()
            )
        if resp is not None and resp.status_code == HTTPStatus.OK:
            # No factor now: recovery must not ask for a code up front.
            self.http_client._needs_otp.pop(self.http_client.username or "", None)
        return resp
