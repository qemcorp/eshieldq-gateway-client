#!/usr/bin/python3

from datetime import datetime, timezone
from http import HTTPStatus
from typing import List
from urllib.parse import quote

from requests import Response

from eshieldq.gateway.schemas.stats import (
    API_STATS_V1,
    API_STATS_V2,
    DpSeries,
    DpStats,
    FileDataModel,
    NameValue,
    StatsStringModel,
)

from .client_base import HttpClient


def _since_qs(since: datetime) -> str:
    # quote: an aware isoformat carries "+00:00"; a raw "+" decodes as space
    return quote(since.isoformat())


class ClientStatsMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client
        # Cached capability probe: None = unknown, True/False after first call.
        # The v2 history endpoints (compact, windowed) supersede v1; older
        # gateways lack them, so we autodetect and fall back to v1.
        self._supports_v2_history: bool | None = None

    def get_stats_string(
        self, api_endpoint: str
    ) -> tuple[Response, StatsStringModel | None]:
        resp = self.http_client.http_get(api_endpoint)

        if resp and resp.status_code == HTTPStatus.OK:
            stats_json = resp.json()
            return resp, StatsStringModel(**stats_json)

        return resp, None

    def get_dp_stats(self, api_endpoint: str) -> tuple[Response, DpStats | None]:
        resp = self.http_client.http_get(api_endpoint)

        if resp and resp.status_code == HTTPStatus.OK:
            stats_json = resp.json()
            return resp, DpStats(**stats_json)

        return resp, None

    def get_history_api(
        self, api_endpoint: str, since: datetime | None = None
    ) -> tuple[Response, list[DpStats]]:

        if since is not None:
            api_endpoint += f"?since={_since_qs(since)}"

        resp = self.http_client.http_get(api_endpoint)

        ret = []
        if resp and resp.status_code == HTTPStatus.OK:
            for k in resp.json():
                ret.append(DpStats(**k))
            return resp, ret
        return resp, ret

    def get_history_series_api(
        self,
        api_endpoint: str,
        window: str = "10m",
        since: datetime | None = None,
    ) -> tuple[Response, DpSeries | None]:
        """Fetch a compact windowed series from a v2 history endpoint."""
        ep = api_endpoint + f"?window={window}"
        if since is not None:
            ep += f"&since={_since_qs(since)}"

        resp = self.http_client.http_get(ep)
        if resp is not None and resp.status_code == HTTPStatus.OK:
            return resp, DpSeries(**resp.json())
        return resp, None

    @staticmethod
    def _series_to_dp_stats(series: DpSeries) -> list[DpStats]:
        """Expand a compact DpSeries into the per-sample DpStats list so
        existing callers keep the same shape regardless of v1/v2.

        A null cell is DROPPED, not coerced. It means the sampler had no value
        for that counter in that bucket, and NameValue.value is an int -- so
        substituting 0 would report a measurement that was never taken, which is
        exactly what made an unavailable cpu_mgmt read as a fully idle control
        plane. Callers already look counters up by name and handle absence.
        """
        out: list[DpStats] = []
        for j, t_ms in enumerate(series.t_ms):
            out.append(
                DpStats(
                    time=datetime.fromtimestamp(t_ms / 1000, tz=timezone.utc),
                    stats=[
                        NameValue(name=name, value=value)
                        for i, name in enumerate(series.names)
                        if (value := series.values[i][j]) is not None
                    ],
                )
            )
        return out

    def _get_counter_history(
        self,
        v1_endpoint: str,
        v2_endpoint: str,
        window: str = "10m",
        since: datetime | None = None,
    ) -> tuple[Response, list[DpStats]]:
        """Prefer the v2 windowed series (autodetected); fall back to v1
        (fixed ~10-minute window) on gateways that lack v2."""
        if self._supports_v2_history is not False:
            resp, series = self.get_history_series_api(
                v2_endpoint, window, since
            )
            if series is not None:
                self._supports_v2_history = True
                return resp, self._series_to_dp_stats(series)
            # 404/405 => endpoint absent on this gateway: remember + fall back.
            if resp is not None and resp.status_code in (
                HTTPStatus.NOT_FOUND,
                HTTPStatus.METHOD_NOT_ALLOWED,
            ):
                self._supports_v2_history = False
            else:
                # Other error (auth/500): surface it rather than misclassify.
                return resp, []

        return self.get_history_api(v1_endpoint, since)

    def get_hw_stats(self, iface_name=None) -> tuple[Response, StatsStringModel | None]:

        iface_ep = ""
        if iface_name:
            iface_ep = f"/{iface_name}"

        return self.get_stats_string(API_STATS_V1 + "/hw" + iface_ep)

    def get_ipsec_stats(self) -> tuple[Response, StatsStringModel | None]:

        return self.get_stats_string(API_STATS_V1 + "/ipsec")

    def get_ipsec_counter_history(
        self, since: datetime | None = None, window: str = "10m"
    ) -> tuple[Response, list[DpStats]]:
        return self._get_counter_history(
            API_STATS_V1 + "/history/ipsec",
            API_STATS_V2 + "/history/ipsec",
            window,
            since,
        )

    def get_ipsec_counter_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/ipsec", window, since
        )

    def get_error_counter_history(
        self, since: datetime | None = None, window: str = "10m"
    ) -> tuple[Response, list[DpStats]]:
        return self._get_counter_history(
            API_STATS_V1 + "/history/errors",
            API_STATS_V2 + "/history/errors",
            window,
            since,
        )

    def get_error_counter_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/errors", window, since
        )

    def get_iface_counter_history(
        self, since: datetime | None = None, window: str = "10m"
    ) -> tuple[Response, list[DpStats]]:
        return self._get_counter_history(
            API_STATS_V1 + "/history/iface",
            API_STATS_V2 + "/history/iface",
            window,
            since,
        )

    def get_iface_counter_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/iface", window, since
        )

    def get_sa_counter_history(
        self, since: datetime | None = None, window: str = "10m"
    ) -> tuple[Response, list[DpStats]]:
        return self._get_counter_history(
            API_STATS_V1 + "/history/sas",
            API_STATS_V2 + "/history/sas",
            window,
            since,
        )

    def get_sa_counter_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/sas", window, since
        )

    def get_runtime_stats(self) -> tuple[Response, StatsStringModel | None]:
        return self.get_stats_string(API_STATS_V1 + "/runtime")

    def get_crypto_handlers(self) -> tuple[Response, StatsStringModel | None]:
        """The live VPP crypto dispatch table (`show crypto handlers`).

        The engine attribution that remains available when the crypto
        execution mode publishes no SecureKey packet counters.
        """
        return self.get_stats_string(API_STATS_V1 + "/crypto-handlers")

    def get_error_stats(
        self,
    ) -> tuple[Response, StatsStringModel | None]:
        return self.get_stats_string(API_STATS_V1 + "/errors")

    def get_error_stats_v2(
        self,
    ) -> tuple[Response, DpStats | None]:
        return self.get_dp_stats(API_STATS_V2 + "/errors")

    def get_iface_stats(self) -> tuple[Response, DpStats | None]:
        return self.get_dp_stats(API_STATS_V1 + "/iface")

    def get_crypto_stats(self) -> tuple[Response, List[FileDataModel]]:

        resp = self.http_client.http_get(API_STATS_V1 + "/crypto")

        resp_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            data = resp.json()
            for k in data:
                resp_list.append(FileDataModel(**k))
        return resp, resp_list

    def get_acl_session_stats(self) -> tuple[Response, DpStats | None]:
        return self.get_dp_stats(API_STATS_V1 + "/acl-session")

    def get_acl_session_details(self) -> tuple[Response, StatsStringModel | None]:
        return self.get_stats_string(API_STATS_V1 + "/acl-session-details")

    def get_acl_session_history(
        self, since: datetime | None = None, window: str = "10m"
    ) -> tuple[Response, list[DpStats]]:
        return self._get_counter_history(
            API_STATS_V1 + "/history/acl-session",
            API_STATS_V2 + "/history/acl-session",
            window,
            since,
        )

    def get_acl_session_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/acl-session", window, since
        )

    def get_resources(self) -> tuple[Response, DpStats | None]:
        return self.get_dp_stats(API_STATS_V1 + "/resources")

    def get_resources_series(
        self, window: str = "10m", since: datetime | None = None
    ) -> tuple[Response, DpSeries | None]:
        return self.get_history_series_api(
            API_STATS_V2 + "/history/resources", window, since
        )
