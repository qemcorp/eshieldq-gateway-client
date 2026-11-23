#!/usr/bin/python3

import json
import time
from http import HTTPStatus
from typing import List

from requests import Response

from eshieldq.gateway.schemas.ipsec import (
    API_IPSEC_V1,
    ActiveSaStatesModel,
    ClientProfileModel,
    ConnCreateModel,
    ConnectionModel,
    ConnectionSaModel,
    IkeSaInitHeadroomModel,
    IkeSettingsModel,
    IkeSettingsStatusModel,
    LoadedConnectionNamesModel,
    NameModel,
    PoolModel,
    RevocationServersModel,
    RevocationStatusModel,
    SaLivenessModel,
    SaRekeyModel,
    SaRekeyResultModel,
    SAModel,
    VpnUserConfigModel,
    VpnUserModel,
)
from eshieldq.gateway.schemas.aaa import (
    AaaProfileModel,
    AaaProfileSetModel,
)
from eshieldq.gateway.schemas.ldap import (
    LdapStatusModel,
    LdapTestResultModel,
    LdapTestUserModel,
)

from .client_base import HttpClient


#: Applying IKE settings restarts the IKE daemon, and the write must not be sent twice.
APPLY_IKE_SETTINGS_TIMEOUT_S = 60

class ClientIpsecMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    def get_loaded_connections(
        self,
    ) -> List[ConnectionModel] | None:
        """Every loaded connection definition, best effort.

        The route behind this returns an empty list both when charon holds
        nothing and when charon could not be asked, so an empty result is not
        evidence that a connection is absent. Use
        `get_loaded_connection_names()` when that is the question.
        """
        resp = self.http_client.http_get(API_IPSEC_V1 + "/connections/loaded")
        if resp and resp.status_code == HTTPStatus.OK:
            ret_list = []
            conn_list = resp.json()
            for sa_dict in conn_list:
                ret_list.append(ConnectionModel(**sa_dict))
            return ret_list

        return None

    def get_loaded_connection_names(self) -> LoadedConnectionNamesModel | None:
        """Which connection definitions charon holds -- authoritatively.

        Use this, not `get_loaded_connections()`, to assert that a connection is
        NOT loaded. That one returns an empty list both when charon holds
        nothing and when charon could not be asked.

        Two different kinds of "unknown", and they are not the same:

        * this method returns **None** -- the appliance did not answer (no
          response, or a status other than 200);
        * it returns a model whose **`names` is None** -- the appliance answered
          and told you charon could not be asked.

        Absence of a name proves absence only when `complete` is true.
        """
        resp = self.http_client.http_get(API_IPSEC_V1 + "/connections/loaded/names")
        if resp and resp.status_code == HTTPStatus.OK:
            return LoadedConnectionNamesModel(**resp.json())
        return None

    def get_loaded_connection_names_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/connections/loaded/names")

    def get_active_sa_states(self) -> ActiveSaStatesModel | None:
        """Which SAs charon holds -- authoritatively.

        Use this, not `get_sas()`, to assert that a tunnel is NOT up: `get_sas()`
        collapses a failed query into an empty list, and the route behind it
        silently omits an SA whose full model will not validate.

        None here means the appliance did not answer; a model whose `sas` is
        None means it answered that charon could not be asked. An SA missing
        from `sas` proves it is down only when `complete` is true.
        """
        resp = self.http_client.http_get(API_IPSEC_V1 + "/sas/states")
        if resp and resp.status_code == HTTPStatus.OK:
            return ActiveSaStatesModel(**resp.json())
        return None

    def get_active_sa_states_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/sas/states")

    def get_ike_sa_init_headroom(self) -> IkeSaInitHeadroomModel | None:
        """Size of the last IKE_SA_INIT, and what the trust set costs it.

        Measured bytes and no fragmentation verdict -- the appliance cannot read
        the MTU that governs. Compare `on_wire_bytes` against a known path MTU.
        """
        resp = self.http_client.http_get(API_IPSEC_V1 + "/ike/sa-init-headroom")
        if resp and resp.status_code == HTTPStatus.OK:
            return IkeSaInitHeadroomModel(**resp.json())

        return None

    def get_ike_sa_init_headroom_response(self) -> Response:
        """The raw response, for a test that must see the exact field set.

        The model-returning wrapper above parses into pydantic, which ignores
        extra fields -- so an assertion that a field is GONE has to read the JSON.
        """
        return self.http_client.http_get(API_IPSEC_V1 + "/ike/sa-init-headroom")

    # ---- IKE admission control and negotiation timing -------------------
    #
    # All three return the full status document, so a caller never has to issue
    # a second GET to learn whether its change is waiting on a restart.

    def get_ike_settings(self) -> IkeSettingsStatusModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/ike/settings")
        if resp and resp.status_code == HTTPStatus.OK:
            return IkeSettingsStatusModel(**resp.json())
        return None

    def get_ike_settings_response(self) -> Response:
        """The raw response, for a test asserting on the exact field set."""
        return self.http_client.http_get(API_IPSEC_V1 + "/ike/settings")

    def set_ike_settings(
        self, settings: IkeSettingsModel
    ) -> tuple[IkeSettingsStatusModel | None, Response]:
        """Store the settings and apply the reload-scoped half.

        Returns the status document, whose `pending_keys` names anything still
        waiting on apply_ike_settings(). Never restarts charon, so no tunnel is
        dropped by this call.
        """
        response = self.http_client.http_put(
            API_IPSEC_V1 + "/ike/settings",
            json=json.loads(settings.model_dump_json()),
        )
        if response is not None and response.status_code == HTTPStatus.OK:
            return IkeSettingsStatusModel(**response.json()), response
        return None, response

    def apply_ike_settings(self) -> tuple[IkeSettingsStatusModel | None, Response]:
        """Restart charon so the load-time settings take effect.

        DESTRUCTIVE: tears down every established IKE and child SA. A no-op when
        nothing load-time is pending.
        """
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/ike/settings/apply", timeout=APPLY_IKE_SETTINGS_TIMEOUT_S
        )
        if response is not None and response.status_code == HTTPStatus.OK:
            return IkeSettingsStatusModel(**response.json()), response
        return None, response

    def reset_ike_settings(self) -> tuple[IkeSettingsStatusModel | None, Response]:
        """Discard the operator configuration and return to the shipped profile."""
        response = self.http_client.http_delete(API_IPSEC_V1 + "/ike/settings")
        if response is not None and response.status_code == HTTPStatus.OK:
            return IkeSettingsStatusModel(**response.json()), response
        return None, response

    def get_revocation_servers(self) -> RevocationStatusModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/revocation/servers")
        if resp and resp.status_code == HTTPStatus.OK:
            return RevocationStatusModel(**resp.json())
        return None

    def set_revocation_servers(
        self, servers: RevocationServersModel
    ) -> tuple[RevocationStatusModel | None, Response]:
        """Store the CRL/OCSP servers and apply them (WAN policy exceptions, then
        the IKE daemon's download switch). A 503 means stored but not applied."""
        response = self.http_client.http_put(
            API_IPSEC_V1 + "/revocation/servers",
            json=json.loads(servers.model_dump_json()),
        )
        if response is not None and response.status_code == HTTPStatus.OK:
            return RevocationStatusModel(**response.json()), response
        return None, response

    def get_saved_connections(
        self,
    ) -> List[ConnCreateModel] | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/connections")
        if resp and resp.status_code == HTTPStatus.OK:
            ret_list = []
            conn_list = resp.json()
            for sa_dict in conn_list:
                ret_list.append(ConnCreateModel(**sa_dict))
            return ret_list

        return None

    def get_conn_in_list(
        self, conn_list: List[ConnectionModel], conn_name: str
    ) -> ConnectionModel | None:
        for conn in conn_list:
            if conn.name == conn_name:
                return conn
        return None

    def get_sas(
        self,
    ) -> List[SAModel]:
        """Every active SA, best effort.

        Lossy in two directions and deliberately kept that way -- the shipped
        web UI consumes this shape. A failed request
        and a null body (charon could not be asked) both come back as an empty
        list, and the route itself omits an SA whose model will not validate. An
        empty result is therefore NOT evidence that no tunnel is up; use
        `get_active_sa_states()` when that is the question.
        """
        ret_list: List[SAModel] = []

        resp = self.http_client.http_get(API_IPSEC_V1 + "/sas")
        if resp and resp.status_code == HTTPStatus.OK:
            sa_list = resp.json()
            if not sa_list:
                return ret_list
            for sa_dict in sa_list:
                ret_list.append(SAModel(**sa_dict))
            return ret_list
        else:
            print(
                f"Failed to get SA list on {self.http_client.address} response: {resp}"
            )
            return ret_list

    def add_connection(
        self,
        conn_model: ConnCreateModel,
        load_conn=True,
        wait_activate_time: float | None = None,
    ) -> tuple[bool, Response]:
        # first upload the connection so its saved
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/connections", json=json.loads(conn_model.model_dump_json())
        )
        ret = self.http_client.check_job_response(response)

        if ret and response.status_code == HTTPStatus.ACCEPTED and load_conn:
            print(f"Loading {conn_model.name}")
            ret, response = self.load_connection(conn_model.name)
            if wait_activate_time:
                time.sleep(wait_activate_time)
        return ret, response

    def modify_connection(
        self,
        conn_name: str,
        conn_model: ConnCreateModel,
        activate=True,
        wait_activate_time: float | None = None,
    ) -> tuple[bool, Response]:
        response = self.http_client.http_put(
            API_IPSEC_V1 + "/connections/" + conn_name,
            json=json.loads(conn_model.model_dump_json()),
        )
        ret = self.http_client.check_job_response(response)

        if ret and response.status_code == HTTPStatus.ACCEPTED and activate:
            print(f"Activating {conn_model.name}")
            ret, response = self.load_connection(conn_model.name)
            if wait_activate_time:
                time.sleep(wait_activate_time)
        return ret, response

    def initiate_child_sa(self, conn_name: str, child_name: str) -> bool:
        data = ConnectionSaModel(
            connection_name=NameModel(name=conn_name),
            sa_name=NameModel(name=child_name),
        )
        json_data = json.loads(data.model_dump_json())
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/initiate-child", json=json_data
        )
        return self.http_client.check_job_response(response)

    def terminate_child_sa(self, conn_name: str, child_name: str) -> bool:
        data = ConnectionSaModel(
            connection_name=NameModel(name=conn_name),
            sa_name=NameModel(name=child_name),
        )
        json_data = json.loads(data.model_dump_json())
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/terminate-child", json=json_data
        )
        return self.http_client.check_job_response(response, ignore_job_failure=True)

    def initiate_ike_conn(self, conn_name: str) -> bool:
        model = NameModel(name=conn_name)
        json_data = json.loads(model.model_dump_json())
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/initiate-ike", json=json_data
        )
        return self.http_client.check_job_response(response)

    def terminate_ike_conn(self, conn_name: str) -> bool:
        model = NameModel(name=conn_name)
        json_data = json.loads(model.model_dump_json())
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/terminate-ike", json=json_data
        )
        return self.http_client.check_job_response(response, ignore_job_failure=True)

    def terminate_session(self, unique_id: str) -> tuple[bool, Response]:
        """Disconnect a single active session by its IKE_SA unique id."""
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/terminate-session/" + str(unique_id)
        )
        return (
            self.http_client.check_job_response(response, ignore_job_failure=True),
            response,
        )

    def get_sa_liveness(self) -> List[SaLivenessModel]:
        """Per-connection forwarding liveness and CHILD_SA census."""
        ret_list: List[SaLivenessModel] = []
        resp = self.http_client.http_get(API_IPSEC_V1 + "/sas/liveness")
        if resp and resp.status_code == HTTPStatus.OK:
            for entry in resp.json() or []:
                ret_list.append(SaLivenessModel(**entry))
        else:
            print(
                f"Failed to get SA liveness on {self.http_client.address} "
                f"response: {resp}"
            )
        return ret_list

    def rekey_sa(
        self,
        conn_name: str,
        child_name: str | None = None,
        reauth: bool = False,
        session_id: str | None = None,
    ) -> SaRekeyResultModel | None:
        """Rekey a CHILD_SA, rekey the IKE_SA, or reauthenticate it.

        Returns None when the request itself failed; a result whose ``matched``
        is 0 means the request was accepted and selected no live SA, which is a
        different outcome and must not be conflated with success.
        """
        model = SaRekeyModel(
            connection_name=conn_name,
            child_name=child_name,
            reauth=reauth,
            session_id=session_id,
        )
        json_data = json.loads(model.model_dump_json())
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/sas/rekey", json=json_data
        )
        if response and response.status_code == HTTPStatus.OK:
            return SaRekeyResultModel(**response.json())
        print(
            f"Failed to rekey SA on {self.http_client.address} response: {response}"
        )
        return None

    def load_connection(self, name: str) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/connections/loaded/" + str(name)
        )
        return self.http_client.check_job_response(response), response

    def unload_connection(self, name: str) -> tuple[bool, Response]:
        response = self.http_client.http_delete(
            API_IPSEC_V1 + "/connections/loaded/" + str(name)
        )
        return self.http_client.check_job_response(response), response

    def delete_connection(self, conn_name: str) -> bool:
        model = NameModel(name=conn_name)
        json_data = json.loads(model.model_dump_json())
        response = self.http_client.http_delete(
            API_IPSEC_V1 + "/connections", json=json_data
        )
        return self.http_client.check_job_response(response)

    def get_pools(self) -> List[PoolModel] | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/pools")
        if resp and resp.status_code == HTTPStatus.OK:
            return [PoolModel(**p) for p in resp.json()]
        return None

    def add_pool(self, pool: PoolModel) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/pools", json=json.loads(pool.model_dump_json())
        )
        return self.http_client.check_job_response(response), response

    def update_pool(self, pool: PoolModel) -> tuple[bool, Response]:
        response = self.http_client.http_put(
            API_IPSEC_V1 + "/pools/" + str(pool.name),
            json=json.loads(pool.model_dump_json()),
        )
        return self.http_client.check_job_response(response), response

    def delete_pool(self, pool_name: str) -> tuple[bool, Response]:
        response = self.http_client.http_delete(
            API_IPSEC_V1 + "/pools/" + str(pool_name)
        )
        return self.http_client.check_job_response(response), response

    def get_client_profile(self, conn_name: str) -> ClientProfileModel | None:
        resp = self.http_client.http_get(
            API_IPSEC_V1 + "/connections/" + str(conn_name) + "/client-profile"
        )
        if resp and resp.status_code == HTTPStatus.OK:
            return ClientProfileModel(**resp.json())
        return None

    # ---- named AAA profiles --------------------------------------------
    #
    # Every RADIUS server and directory is configured as a named profile.
    # Secrets are write-only in both directions: nothing here can read a stored
    # shared secret or bind password back.

    def get_aaa_profiles(self) -> list[AaaProfileModel]:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/aaa/profiles")
        if resp and resp.status_code == HTTPStatus.OK and resp.json() is not None:
            return [AaaProfileModel(**entry) for entry in resp.json()]
        return []

    def get_aaa_profiles_response(self) -> Response:
        """The raw bytes, for a secret-leak check.

        Through the wrapper rather than a hand-written path: a hand-written one
        silently probes an endpoint that does not exist and can never fail.
        """
        return self.http_client.http_get(API_IPSEC_V1 + "/aaa/profiles")

    def get_aaa_profile(self, name: str) -> AaaProfileModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + f"/aaa/profiles/{name}")
        if resp and resp.status_code == HTTPStatus.OK and resp.json() is not None:
            return AaaProfileModel(**resp.json())
        return None

    def set_aaa_profile(self, profile: AaaProfileSetModel) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/aaa/profiles",
            json=json.loads(profile.model_dump_json()),
        )
        return (
            response is not None
            and response.status_code == HTTPStatus.NO_CONTENT
        ), response

    def delete_aaa_profile(self, name: str) -> tuple[bool, Response]:
        response = self.http_client.http_delete(
            API_IPSEC_V1 + f"/aaa/profiles/{name}"
        )
        return (
            response is not None
            and response.status_code == HTTPStatus.NO_CONTENT
        ), response

    # Raw-response readers. A secret-leak check needs the bytes the API actually
    # returned, not a parsed model -- but it still must not hand-write the path,
    # or it silently probes an endpoint that does not exist and can never fail.
    def get_vpn_users_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/users")

    def get_saved_connections_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/connections")

    def get_ldap_status(self) -> LdapStatusModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/ldap/status")
        if resp and resp.status_code == HTTPStatus.OK:
            return LdapStatusModel(**resp.json())
        return None

    def test_ldap(self) -> LdapTestResultModel | None:
        resp = self.http_client.http_post(API_IPSEC_V1 + "/ldap/test")
        if resp and resp.status_code == HTTPStatus.OK:
            return LdapTestResultModel(**resp.json())
        return None

    def test_ldap_user(self, username: str, password: str) -> LdapTestResultModel | None:
        """Probe one user's credentials. The password is write-only server-side:
        never stored, never logged, never returned."""
        probe = LdapTestUserModel(username=username, password=password)
        resp = self.http_client.http_post(
            API_IPSEC_V1 + "/ldap/test-user", json=json.loads(probe.model_dump_json())
        )
        if resp and resp.status_code == HTTPStatus.OK:
            return LdapTestResultModel(**resp.json())
        return None

    def test_ldap_user_response(self, username: str, password: str) -> Response:
        """`test_ldap_user` returning the raw response, for callers asserting on
        the status code (the 429 that proves the probe is rate limited)."""
        probe = LdapTestUserModel(username=username, password=password)
        return self.http_client.http_post(
            API_IPSEC_V1 + "/ldap/test-user", json=json.loads(probe.model_dump_json())
        )

    def get_vpn_users(self) -> List[VpnUserModel] | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/users")
        if resp and resp.status_code == HTTPStatus.OK:
            return [VpnUserModel(**u) for u in resp.json()]
        return None

    def set_vpn_user(self, user: VpnUserConfigModel) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/users", json=json.loads(user.model_dump_json())
        )
        return self.http_client.check_job_response(response), response

    def delete_vpn_user(self, username: str) -> tuple[bool, Response]:
        response = self.http_client.http_delete(
            API_IPSEC_V1 + "/users/" + str(username)
        )
        return self.http_client.check_job_response(response), response
