import json
import secrets
from typing import Dict, Optional, Any
from urllib.parse import urlencode
from fastapi import Request
from fastapi.encoders import jsonable_encoder

import requests
from redis import Redis
from starlette.responses import JSONResponse, Response

from app.services.jwt_service import JwtService
from app.services.template_service import TemplateService
from app.services.app_provider import AppProvider
from app.utils import rand_pass
from app.models.authorize_request import AuthorizeRequest
from app.models.token_request import TokenRequest


class OidcService:
    def __init__(
        self,
        redis_client: Redis,
        jwt_service: JwtService,
        register_base_url: str,
        identities: Dict[str, str],
        pyop_provider: AppProvider,
        template_service: TemplateService,
        identities_page_sidebar_template: Optional[str],
    ):
        self._redis_client = redis_client
        self._jwt_service = jwt_service
        self._register_base_url = register_base_url
        self._identities = identities
        self._pyop_provider = pyop_provider
        self._templates = template_service.templates
        self.identities_page_sidebar_template = identities_page_sidebar_template

    def authorize(
        self, request: Request, authorize_request: AuthorizeRequest
    ) -> Response:
        session_key = rand_pass(100)
        self._redis_client.set(
            "authorize_" + session_key, json.dumps(authorize_request.dict())
        )

        scopes = authorize_request.scope.split(" ")
        if "identities" in scopes:
            template_context = {
                "layout": "layout.html",
                "request": request,
                "state": session_key,
                "identities": self._identities,
            }

            if self.identities_page_sidebar_template:
                template_context["sidebar"] = self.identities_page_sidebar_template

            return self._templates.TemplateResponse(
                "identities.html",
                template_context,
            )
        return self._templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "state": session_key,
            },
        )

    def submit(self, body: Dict[str, Any], request: Request) -> Response:
        if "bsn" not in body or "state" not in body:
            return Response(status_code=400)

        bsn = body["bsn"]
        state = body["state"]
        authorize_state = self._redis_client.get("authorize_" + state)
        if authorize_state is None:
            raise RuntimeError("Invalid state")
        authorize_state = json.loads(authorize_state.decode("utf-8"))

        resp = requests.get(
            self._register_base_url + "/signed-userinfo?bsn=" + bsn,
            timeout=30,
        )
        if resp.status_code != 200:
            redirect_uri = authorize_state["redirect_uri"]
            append_symbol = (
                "&" if redirect_uri is not None and "?" in redirect_uri else "?"
            )
            redirect_with_error = (
                redirect_uri
                + append_symbol
                + urlencode(
                    {
                        "state": authorize_state["state"],
                        "error": "invalid_request",
                        "error_description": "service is unavailable",
                    }
                )
            )
            return JSONResponse({"redirect_url": redirect_with_error})

        client_public_key = self._pyop_provider.get_client_public_key(
            authorize_state["client_id"]
        )
        userinfo = self._jwt_service.create_jwe(
            client_public_key, {"signed_userinfo": resp.json()["signed_userinfo"]}
        )

        access_token = secrets.token_urlsafe(96)[:64]
        self._redis_client.set("userinfo_" + access_token, userinfo)

        code = secrets.token_urlsafe(96)[:64]

        py_op_authorize_request = self._pyop_provider.parse_authentication_request(
            authorize_state, request.headers
        )
        authorize_response = self._pyop_provider.authorize(py_op_authorize_request, "_")
        print("authorzie_respons\n", authorize_response)

        self._redis_client.set("access_token_" + code, access_token)

        redirect_url = (
            authorize_state["redirect_uri"]
            + "?"
            + urlencode({"state": authorize_state["state"], "code": code})
        )
        return Response(json.dumps({"redirect_url": redirect_url}))

    def handle_submit(self, body: Dict[str, Any], request: Request) -> Response:
        if "login_hint" not in body:
            return Response(status_code=400)

        if "signed_userinfo" not in body or "state" not in body:
            return Response(status_code=400)

        if body["login_hint"] == "identities":
            return self.submit(body, request)

        signed_userinfo = body["signed_userinfo"]
        state = body["state"]

        authorize_cache = self._redis_client.get("authorize_" + state)
        if authorize_cache is None:
            raise RuntimeError("Invalid state")

        authorize_state = json.loads(authorize_cache.decode("utf-8"))

        authorize_response = self._pyop_provider.authorize_client(
            authorize_state, request.headers
        )

        client_public_key = self._pyop_provider.get_client_public_key(
            authorize_state["client_id"]
        )
        userinfo = self._jwt_service.create_jwe(
            client_public_key, {"signed_userinfo": signed_userinfo}
        )

        self._redis_client.set("userinfo_" + authorize_response["code"], userinfo)

        redirect_url = (
            authorize_state["redirect_uri"]
            + "?"
            + urlencode(
                {"state": authorize_state["state"], "code": authorize_response["code"]}
            )
        )
        return Response(json.dumps({"redirect_url": redirect_url}))

    def get_userinfo_token_from_register(
        self, bsn: str, userinfo_validity_in_seconds: Optional[str] = None
    ) -> Response:
        append_symbol = "&" if "?" in self._register_base_url else "?"
        params = (
            {"bsn": bsn, "userinfo_validity_in_seconds": userinfo_validity_in_seconds}
            if userinfo_validity_in_seconds is not None
            else {"bsn": bsn}
        )
        signed_userinfo_endpoint = (
            self._register_base_url
            + "/signed-userinfo"
            + append_symbol
            + urlencode(params)
        )

        response = requests.get(
            signed_userinfo_endpoint,
            timeout=30,
        )

        if response.status_code != 200:
            return Response(status_code=400)

        return JSONResponse(response.json())

    def token(self, token_request: TokenRequest, request: Request) -> Response:
        token_response = self._pyop_provider.handle_token_request(
            token_request.query_string, request.headers
        )

        # bind userinfo to token
        userinfo = self._redis_client.get("userinfo_" + token_request.code)
        self._redis_client.delete("userinfo_" + token_request.code)
        self._redis_client.set("userinfo_" + token_response["access_token"], userinfo)

        return token_response

    def userinfo(self, request: Request) -> Response:
        access_token = self._pyop_provider.extract_bearer_token_from_http_request(
            authz_header=request.headers.get("Authorization")
        )

        if access_token is None:
            # access denied
            return Response(status_code=401)

        access_token_active = self._pyop_provider.introspect_access_token(access_token)
        if not access_token_active:
            return Response(status_code=401)

        userinfo = self._redis_client.get("userinfo_" + access_token)
        if userinfo is None:
            return Response(status_code=401)

        return Response(content=userinfo, media_type="application/jwt")

    def get_jwks(self) -> JSONResponse:
        return JSONResponse(content=jsonable_encoder(self._pyop_provider.jwks))

    def get_well_known_openid_config(self) -> JSONResponse:
        return JSONResponse(
            jsonable_encoder(self._pyop_provider.configuration_information)
        )
