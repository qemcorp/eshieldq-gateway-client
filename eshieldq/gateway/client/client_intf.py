#!/usr/bin/python3

import json
from http import HTTPStatus
from typing import List

from requests import Response

from eshieldq.gateway.schemas.inet import FibRouteModel, IpModel, IpSubnetModel, RouteModel, RouteReplaceModel
from eshieldq.gateway.schemas.intf import (
    API_INTERFACES_V1,
    IfaceRoleSet,
    IfaceRoleTypes,
    IfaceSettings,
)

from .client_base import HttpClient


class ClientIntfMgr:
    """Interfaces are selected by role (wan, lan, mgmt), never by VPP name."""

    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    def get_interface_roles(self) -> tuple[Response, List[IfaceSettings]]:
        """The WAN, LAN and management interfaces."""
        resp = self.http_client.http_get(API_INTERFACES_V1 + "/roles")
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, [IfaceSettings(**d) for d in resp.json()]
        return resp, []

    def get_interface_by_role(self, role: IfaceRoleTypes | str) -> tuple[Response, IfaceSettings | None]:
        role = IfaceRoleTypes(role)
        resp = self.http_client.http_get(API_INTERFACES_V1 + f"/roles/{role.value}")
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, IfaceSettings(**resp.json())
        return resp, None

    def get_lan_interface(self) -> IfaceSettings | None:
        return self.get_interface_by_role(IfaceRoleTypes.LAN)[1]

    def get_wan_interface(self) -> IfaceSettings | None:
        return self.get_interface_by_role(IfaceRoleTypes.WAN)[1]

    def get_interface_ips(self, role: IfaceRoleTypes | str) -> tuple[Response, List[IpSubnetModel]]:
        resp, iface = self.get_interface_by_role(role)
        return resp, [] if iface is None else iface.ip_addrs

    def set_interface_roles(self, wan_mac_addr: str, lan_mac_addr: str) -> Response:

        subnet_data = json.loads(
            IfaceRoleSet(
                wan_mac_addr=wan_mac_addr, lan_mac_addr=lan_mac_addr
            ).model_dump_json()
        )
        return self.http_client.http_post(API_INTERFACES_V1 + "/roles", json=subnet_data)

    @staticmethod
    def _subnet(addr: str) -> dict:
        return json.loads(IpSubnetModel(subnet=addr).model_dump_json())  # type: ignore

    def set_interface_ip(self, role: IfaceRoleTypes | str, addr: str) -> Response:
        role = IfaceRoleTypes(role)
        return self.http_client.http_post(
            API_INTERFACES_V1 + f"/roles/{role.value}/ips", json=self._subnet(addr)
        )

    def del_interface_ip(self, role: IfaceRoleTypes | str, ip_subnet: str) -> Response:
        role = IfaceRoleTypes(role)
        return self.http_client.http_delete(
            API_INTERFACES_V1 + f"/roles/{role.value}/ips", json=self._subnet(ip_subnet)
        )

    def get_forwarding_table(self) -> tuple[Response, list[FibRouteModel] | None]:
        """The dataplane forwarding table, IPv4 and IPv6, every table."""
        resp = self.http_client.http_get(API_INTERFACES_V1 + "/forwarding-table")
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, [FibRouteModel(**r) for r in resp.json()]
        return resp, None

    def get_saved_routes(self) -> tuple[Response, list[RouteModel] | None]:
        resp = self.http_client.http_get(API_INTERFACES_V1 + "/routes")
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, [RouteModel(**r) for r in resp.json()]
        return resp, None

    @staticmethod
    def _route(ip_subnet: str, interface_role: IfaceRoleTypes | str | None, gateway_ip: str | None) -> dict:
        return json.loads(
            RouteModel(
                ip_subnet=IpSubnetModel(subnet=ip_subnet),  # type: ignore
                gateway_ip=IpModel(ip=gateway_ip) if gateway_ip else None,  # type: ignore
                interface_role=None if interface_role is None else IfaceRoleTypes(interface_role),  # type: ignore
            ).model_dump_json()
        )

    def add_ip_route(
        self, ip_subnet: str, interface_role: IfaceRoleTypes | str | None, gateway_ip: str | None
    ) -> Response:
        return self.http_client.http_post(
            API_INTERFACES_V1 + "/routes", json=self._route(ip_subnet, interface_role, gateway_ip)
        )

    def delete_ip_route(
        self, ip_subnet: str, interface_role: IfaceRoleTypes | str | None, gateway_ip: str | None
    ) -> Response:
        return self.http_client.http_delete(
            API_INTERFACES_V1 + "/routes", json=self._route(ip_subnet, interface_role, gateway_ip)
        )

    def replace_ip_route(
        self, current: RouteModel, new: RouteModel
    ) -> tuple[Response, RouteModel | None]:
        data = json.loads(RouteReplaceModel(current=current, new=new).model_dump_json())
        resp = self.http_client.http_put(API_INTERFACES_V1 + "/routes", json=data)
        if resp and resp.status_code == HTTPStatus.OK:
            return resp, RouteModel(**resp.json())
        return resp, None
