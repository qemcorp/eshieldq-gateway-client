#!/usr/bin/python3

import json
import time
from http import HTTPStatus
from typing import List

from requests import Response

from eshieldq.gateway.schemas.ipsec import (
    API_IPSEC_V1,
    ClientProfileModel,
    ConnCreateModel,
    ConnectionModel,
    ConnectionSaModel,
    NameModel,
    PoolModel,
    RadiusServerConfigModel,
    RadiusServerModel,
    SaLivenessModel,
    SaRekeyModel,
    SaRekeyResultModel,
    SAModel,
    VpnUserConfigModel,
    VpnUserModel,
)
from eshieldq.gateway.schemas.ldap import (
    LdapConfigModel,
    LdapSetConfigModel,
    LdapStatusModel,
    LdapTestResultModel,
    LdapTestUserModel,
)

from .client_base import HttpClient


class ClientIpsecMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    def get_loaded_connections(
        self,
    ) -> List[ConnectionModel] | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/connections/loaded")
        if resp and resp.status_code == HTTPStatus.OK:
            ret_list = []
            conn_list = resp.json()
            for sa_dict in conn_list:
                ret_list.append(ConnectionModel(**sa_dict))
            return ret_list

        return None

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

    def get_radius(self) -> RadiusServerModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/radius")
        if resp and resp.status_code == HTTPStatus.OK and resp.json() is not None:
            return RadiusServerModel(**resp.json())
        return None

    # Raw-response readers. A secret-leak check needs the bytes the API actually
    # returned, not a parsed model -- but it still must not hand-write the path,
    # or it silently probes an endpoint that does not exist and can never fail.
    def get_radius_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/radius")

    def get_vpn_users_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/users")

    def get_saved_connections_response(self) -> Response:
        return self.http_client.http_get(API_IPSEC_V1 + "/connections")

    def set_radius(self, config: RadiusServerConfigModel) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/radius", json=json.loads(config.model_dump_json())
        )
        return self.http_client.check_job_response(response), response

    def delete_radius(self) -> tuple[bool, Response]:
        response = self.http_client.http_delete(API_IPSEC_V1 + "/radius")
        return self.http_client.check_job_response(response), response

    def get_ldap(self) -> LdapConfigModel | None:
        resp = self.http_client.http_get(API_IPSEC_V1 + "/ldap")
        if resp and resp.status_code == HTTPStatus.OK and resp.json() is not None:
            return LdapConfigModel(**resp.json())
        return None

    def set_ldap(self, config: LdapSetConfigModel) -> tuple[bool, Response]:
        response = self.http_client.http_post(
            API_IPSEC_V1 + "/ldap", json=json.loads(config.model_dump_json())
        )
        return (
            response is not None
            and response.status_code == HTTPStatus.NO_CONTENT
        ), response

    def delete_ldap(self) -> tuple[bool, Response]:
        response = self.http_client.http_delete(API_IPSEC_V1 + "/ldap")
        return (
            response is not None
            and response.status_code == HTTPStatus.NO_CONTENT
        ), response

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
