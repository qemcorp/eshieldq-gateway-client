#!/usr/bin/python3


import json
from http import HTTPStatus
from ipaddress import IPv4Network
from typing import List

from requests import Response

from eshieldq.gateway.schemas.acl import (
    API_ACL_V1,
    AclAction,
    AclStats,
    IpAclRule,
    IpProtocol,
    MacIpAclRule,
)
from eshieldq.gateway.schemas.intf import IfaceRoleTypes
from eshieldq.gateway.schemas.stats import DpStats

from .client_base import HttpClient


class ClientAclMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    @staticmethod
    def revision_of(resp: Response) -> str | None:
        """The concurrency token of the set a response describes.

        `GET /rules/{ip,macip}` publishes it, and every write echoes the one it
        left behind, so a read-modify-write can pass it straight back as
        `if_match`. Opaque: it is a digest of the stored rows in stored
        order, which is not the order the GET returns, so echo it rather than
        trying to compute one.
        """
        return resp.headers.get("ETag") if resp is not None else None

    @staticmethod
    def _if_match(if_match: str | None) -> dict:
        # `is not None`, not truthiness: only None means "no precondition". An
        # empty string is a malformed field the server answers 400, and silently
        # dropping it would turn a caller's missing-token bug into exactly the
        # unconditional whole-set write this header exists to prevent.
        return {"headers": {"If-Match": if_match}} if if_match is not None else {}

    def get_acl_rules(
        self,
    ) -> tuple[Response, list[IpAclRule]]:
        resp = self.http_client.http_get(API_ACL_V1 + "/rules/ip")
        ret_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            for dict in resp.json():
                # read back without the request check: a legacy row must still list
                ret_list.append(IpAclRule.from_stored(dict))
            return resp, ret_list
        return resp, []

    def get_acl_rules_for_interface(
        self,
        interface: IfaceRoleTypes,
    ) -> tuple[Response, list[IpAclRule]]:
        resp = self.http_client.http_get(f"{API_ACL_V1}/rules/ip/{interface.value}")
        ret_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            for dict in resp.json():
                # read back without the request check: a legacy row must still list
                ret_list.append(IpAclRule.from_stored(dict))
            return resp, ret_list
        return resp, []

    def add_acl_rule(
        self,
        rule: IpAclRule,
    ) -> Response:
        data = json.loads(rule.model_dump_json())

        resp = self.http_client.http_post(API_ACL_V1 + "/rules/ip", json=data)
        return resp

    def set_acl_rules(
        self,
        rules: List[IpAclRule],
        if_match: str | None = None,
    ) -> Response:
        """Replace the whole IP rule set.

        `if_match` is the token from the read this set was derived from. Pass
        it for a read-modify-write and the gateway answers 412 instead of
        reverting whatever another operator changed in between; omit it for an
        unconditional replace (a restore, a first write, `delete_all`).
        """
        data = []
        for r in rules:
            data.append(json.loads(r.model_dump_json()))

        resp = self.http_client.http_put(
            API_ACL_V1 + "/rules/ip", json=data, **self._if_match(if_match)
        )
        return resp

    def get_acl_rule_stats(
        self,
    ) -> tuple[Response, list[AclStats]]:
        resp = self.http_client.http_get(API_ACL_V1 + "/stats/ip")
        ret_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            for dict in resp.json():
                ret_list.append(AclStats(**dict))
            return resp, ret_list
        return resp, []

    def get_acl_ip_drop_stats(
        self,
    ) -> tuple[Response, DpStats | None]:
        resp = self.http_client.http_get(API_ACL_V1 + "/stats/errors")
        ret = None
        if resp and resp.status_code == HTTPStatus.OK:
            dict = resp.json()
            ret = DpStats(**dict)
            return resp, ret
        return resp, ret

    def set_macip_rules(
        self,
        rules: List[MacIpAclRule],
        if_match: str | None = None,
    ) -> Response:
        """Replace the whole MACIP rule set; `if_match` as in set_acl_rules."""
        data = []
        for r in rules:
            data.append(json.loads(r.model_dump_json()))

        resp = self.http_client.http_put(
            API_ACL_V1 + "/rules/macip", json=data, **self._if_match(if_match)
        )
        return resp

    def delete_acl_rule(
        self,
        rule: IpAclRule,
        if_match: str | None = None,
    ) -> Response:
        """Delete one IP rule.

        `if_match` matters more here than it looks: rule equality ignores
        priority, so a delete built from a stale read still matches a rule
        whose priority someone else has changed since.
        """
        data = json.loads(rule.model_dump_json())

        resp = self.http_client.http_delete(
            API_ACL_V1 + "/rules/ip", json=data, **self._if_match(if_match)
        )
        return resp

    def delete_all_acl_rules(self) -> Response:
        # delete all acl rules using a set with an empty list
        return self.set_acl_rules([])

    def delete_all_macip_rules(self) -> Response:
        # delete all rules using a set with an empty list
        return self.set_macip_rules([])

    def get_macip_acl_rules(
        self,
    ) -> tuple[Response, list[MacIpAclRule]]:
        resp = self.http_client.http_get(API_ACL_V1 + "/rules/macip")
        ret_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            for dict in resp.json():
                ret_list.append(MacIpAclRule(**dict))
            return resp, ret_list
        return resp, []

    def get_macip_acl_rules_for_interface(
        self,
        interface: IfaceRoleTypes,
    ) -> tuple[Response, list[MacIpAclRule]]:
        resp = self.http_client.http_get(f"{API_ACL_V1}/rules/macip/{interface.value}")
        ret_list = []
        if resp and resp.status_code == HTTPStatus.OK:
            for dict in resp.json():
                ret_list.append(MacIpAclRule(**dict))
            return resp, ret_list
        return resp, []

    def add_macip_acl_rule(
        self,
        rule: MacIpAclRule,
    ) -> Response:
        data = json.loads(rule.model_dump_json())

        resp = self.http_client.http_post(API_ACL_V1 + "/rules/macip", json=data)
        return resp

    def delete_macip_acl_rule(
        self,
        rule: MacIpAclRule,
        if_match: str | None = None,
    ) -> Response:
        """Delete one MACIP rule; `if_match` as in delete_acl_rule."""
        data = json.loads(rule.model_dump_json())

        resp = self.http_client.http_delete(
            API_ACL_V1 + "/rules/macip", json=data, **self._if_match(if_match)
        )
        return resp

    def set_acl_allow_all(self) -> bool:
        for is_input in [True, False]:
            for role in [IfaceRoleTypes.LAN, IfaceRoleTypes.WAN]:
                rule = IpAclRule(
                    is_permit=AclAction.ACL_ACTION_API_PERMIT,
                    src_prefix=IPv4Network("0.0.0.0/0"),
                    dst_prefix=IPv4Network("0.0.0.0/0"),
                    proto=IpProtocol.IP_API_PROTO_HOPOPT,
                    src_port_first=0,
                    src_port_last=65535,
                    dst_port_first=0,
                    dst_port_last=65535,
                    tcp_flags_mask=0,
                    tcp_flags_value=0,
                    is_input=is_input,
                    priority=0,
                    interface_role=role,
                )
                resp = self.add_acl_rule(rule=rule)
                if not resp.status_code == HTTPStatus.OK:
                    return False
        return True

    def clear_acl_sessions(
        self,
    ) -> Response:

        resp = self.http_client.http_post(API_ACL_V1 + "/clear-sessions")
        return resp
