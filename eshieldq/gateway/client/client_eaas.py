#!/usr/bin/python3
import json
from http import HTTPStatus

from requests import Response
from eshieldq.gateway.schemas.eaas import (
    API_EAAS_V1,
    EaaSAction,
    EaasBaseModel,
    EaasSecretDataModel,
    EaasServiceControlModel,
    EaasStatusModel,
)

from .client_base import HttpClient


class ClientEaaSMgr:
    def __init__(self, http_client: HttpClient) -> None:
        self.http_client = http_client

    def upload_eaas_secret(
        self, secret: str, type: str = "QEM"
    ) -> tuple[Response, EaasBaseModel | None]:
        data = EaasSecretDataModel(id=None, type=type, secret=secret).model_dump()

        response = self.http_client.http_post(API_EAAS_V1 + "/eaas_secret", json=data)
        # parse response for EaasBaseModel
        if response and response.status_code == HTTPStatus.ACCEPTED:
            resp_json = response.json()
            eaas_secret = EaasBaseModel(**resp_json)
            return response, eaas_secret
        else:
            return response, None

    def get_eaas_secrets(self) -> tuple[Response, list[EaasBaseModel] | None]:
        resp = self.http_client.http_get(API_EAAS_V1 + "/eaas_secrets")
        if resp and resp.status_code == HTTPStatus.OK:
            resp_json = resp.json()
            eaas_secrets = [EaasBaseModel(**eaas) for eaas in resp_json]
            return resp, eaas_secrets
        else:
            return resp, None

    def delete_eaas_secrets(self, type: str = "QEM", id=None) -> Response:

        resp = self.http_client.http_delete(
            API_EAAS_V1 + "/eaas_secrets",
            json=[EaasBaseModel(id=None, type=type).model_dump()],
        )
        return resp

    def get_eaas_status(self) -> tuple[Response, EaasStatusModel | None]:
        """Return health, retrieval metadata, and optional validated kernel feeds.

        Older appliances omit feed fields; their values remain None.
        """
        resp = self.http_client.http_get(API_EAAS_V1 + "/eaas_status")
        if resp and resp.status_code == HTTPStatus.OK:
            resp_json = resp.json()
            eaas_status = EaasStatusModel(**resp_json)
            return resp, eaas_status
        else:
            return resp, None

    def restart_eaas_service(self) -> tuple[Response, bool]:
        data = json.loads(
            EaasServiceControlModel(
                action=EaaSAction.EAAS_ACTION_RESTART
            ).model_dump_json()
        )

        resp = self.http_client.http_post(API_EAAS_V1 + "/eaas_control", json=data)
        return resp, self.http_client.check_job_response(resp)

    def start_eaas_service(self) -> tuple[Response, bool]:
        data = json.loads(
            EaasServiceControlModel(
                action=EaaSAction.EAAS_ACTION_START
            ).model_dump_json()
        )

        resp = self.http_client.http_post(API_EAAS_V1 + "/eaas_control", json=data)
        return resp, self.http_client.check_job_response(resp)

    def stop_eaas_service(self) -> tuple[Response, bool]:
        data = json.loads(
            EaasServiceControlModel(
                action=EaaSAction.EAAS_ACTION_STOP
            ).model_dump_json()
        )

        resp = self.http_client.http_post(API_EAAS_V1 + "/eaas_control", json=data)
        return resp, self.http_client.check_job_response(resp)
