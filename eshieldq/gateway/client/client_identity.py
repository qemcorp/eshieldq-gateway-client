"""Client for the device identity / license status surface.

The status model carries the device's own `birth_cert.valid` / `license.valid`
self-report plus the raw artifacts (birth-cert PEM, license JWT) needed to check
it independently. Verifying them against operator-supplied trust anchors is
deliberately NOT here: it needs the license verification primitives, which live
not provided here: this module reports the device's own view only."""

from __future__ import annotations

from http import HTTPStatus

from requests import Response
from eshieldq.gateway.schemas.identity import API_IDENTITY_V1, DeviceLicenseStatusModel

from .client_base import HttpClient


class ClientIdentityMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    def get_status(self) -> DeviceLicenseStatusModel | None:
        response = self.http_client.http_get(API_IDENTITY_V1 + "/status")
        if response and response.status_code == HTTPStatus.OK:
            return DeviceLicenseStatusModel(**response.json())
        return None

    def get_status_response(self) -> Response:
        """The raw status response, for callers that assert on the status code
        (an unenrolled or rel device is a legitimate non-200)."""
        return self.http_client.http_get(API_IDENTITY_V1 + "/status")

    def is_healthy(self) -> bool | None:
        """The operational health REPORT, or None when status is unavailable.

        Use for alerting. This goes false when the device-key measurement stops being
        refreshed, which is a real fault -- but not one that should stop an update, so
        do not gate updates on it (see is_update_ready)."""
        status = self.get_status()
        return None if status is None else status.healthy

    def is_update_ready(self) -> bool | None:
        """Whether the device should be OFFERED an update, or None when unavailable.

        Distinct from is_healthy on purpose: an update is gated on the live
        proof-of-possession the device signs at update time, so a stale or
        missing cached measurement does not disqualify it."""
        status = self.get_status()
        return None if status is None else status.update_ready

    def key_status_age(self) -> float | None:
        """Seconds since the device-key measurement was published; None when it has
        never been published or status is unavailable. A large age means the publisher
        stopped, which `pop_signing_ok is None` alone cannot tell you."""
        status = self.get_status()
        return None if status is None else status.identity.key_status_age_seconds

    def enroll(self, force: bool = False) -> Response:
        """Re-arm the device's enrollment retry loop. Returns the raw response:
        the device may legitimately answer non-200 while it is still retrying.

        `force` RE-enrolls a device that is already enrolled, replacing its birth
        cert and licence. That is how a device picks up an entitlement minted after
        it enrolled -- the licence is issued once and never re-evaluated -- and the
        device half of an administrative registry reset. Admin only; a non-admin
        gets 403.

        Do NOT poll `healthy` for completion: on an already-enrolled device it is
        true before, during and after a FAILED force. Poll enroll_result().
        """
        return self.http_client.http_post(
            API_IDENTITY_V1 + "/enroll", json={"force": force}
        )

    def enroll_result(self) -> dict | None:
        """The agent's terminal record for the most recent forced enrollment.

        `state` is none/running/done/failed; a failure carries the Authority's own
        `reason` and `detail`. The agent is the only party that sees the Authority's
        answer, which is why this exists rather than deriving it from status."""
        response = self.http_client.http_get(API_IDENTITY_V1 + "/enroll/result")
        if response and response.status_code == HTTPStatus.OK:
            return response.json()
        return None

    def wait_enroll_result(
        self, timeout: int = 300, interval: float = 5.0, *, not_id: str | None = None
    ) -> dict | None:
        """Block until a forced enrollment reaches a terminal state, or time out.

        Returns the terminal record, or None on timeout. Callers assert on `state`;
        a timeout is deliberately not an exception, because a device that is still
        retrying is a legitimate outcome the caller may want to report differently.

        `not_id` is the operation id seen BEFORE the force was requested. Pass it and any
        terminal record still carrying that id is ignored as the previous operation's.
        Without it this returns whatever terminal record is there, which on a device that
        has been forced before is the OLD outcome -- read within the first poll, so a
        re-enrollment that had not begun reports done (or, worse, reports the earlier
        run's failure). `enroll_result()["id"]` before forcing is where the value comes
        from; there is no need to know the new id, only that it is different.
        """
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            got = self.enroll_result()
            if got and got.get("state") in ("done", "failed"):
                if not_id is None or got.get("id") != not_id:
                    return got
            time.sleep(interval)
        return None
