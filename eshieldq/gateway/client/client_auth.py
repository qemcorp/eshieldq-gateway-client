#!/usr/bin/python3


from contextlib import contextmanager
from http import HTTPStatus

from requests import Response
from eshieldq.gateway.schemas.auth import (
    API_AUTH_V1,
    API_AUTH_V2,
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

    def user_login(self, username="user", password="string", otp_value=None):
        login = {
            "username": username,
            "password": password,
            "scope": "",
            "client_id": None,
            "client_secret": otp_value,
        }
        # v2 first (cookie based); v1 only on a 404, never on an exception.
        resp = self.http_client.http_post(API_AUTH_V2 + "/token", data=login)
        if resp.status_code == HTTPStatus.NOT_FOUND:
            return self.http_client.http_post(API_AUTH_V1 + "/token", data=login)
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

        return self.http_client.http_post(API_AUTH_V1 + "/change-password", json=login)

    def get_auth_settings(self) -> tuple[Response, SysSecuritySettings | None]:
        resp = self.http_client.http_get(API_AUTH_V1 + "/settings")
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, SysSecuritySettings(**resp.json())

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
        here would have every `set_auth_settings(otp_enforce=True)` in the
        product and the harness quietly reset an operator's lockout policy.
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

        resp = self.http_client.http_post(API_AUTH_V1 + "/settings", json=data)
        return resp

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
            resp = self.http_client.http_post(API_AUTH_V1 + "/otp/enroll", json=data)
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
            return self.http_client.http_post(API_AUTH_V1 + "/otp/enable", json=data)

    def user_otp_disable(self, password: str, otp_value: str) -> Response:
        data = {"password": password, "otp_value": otp_value}
        with self._no_relogin():
            return self.http_client.http_post(API_AUTH_V1 + "/otp/disable", json=data)
