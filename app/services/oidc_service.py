import json
import secrets
from typing import Dict, Optional, Any
from urllib.parse import urlencode
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from pyop.provider import Provider as PyopProvider,  AuthorizationRequest
from pyop.access_token import AccessToken

import requests
from redis import Redis
from starlette.responses import JSONResponse, Response

from app.services.jwt_service import JwtService
from app.services.template_service import TemplateService
from app.services.app_provider import AppProvider
from app.utils import rand_pass, load_jwk
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
        scopes = authorize_request.scope.split(" ")
        session_key = rand_pass(100)
        # authorize_state = {
        #     "redirect_uri": authorize_request.redirect_uri,
        #     "state": authorize_request.state,
        #     "client_id": authorize_request.client_id,
        # }
        authorize_state = authorize_request.dict()
        self._redis_client.set("authorize_" + session_key, json.dumps(authorize_state))
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

        client_public_key_path = self._get_pyop_provider_client_secret_path(
            authorize_state["client_id"]
        )
        client_public_key = load_jwk(client_public_key_path)

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

        authorize_state = self._redis_client.get("authorize_" + state)
        if authorize_state is None:
            raise RuntimeError("Invalid state")

        authorize_state = json.loads(authorize_state.decode("utf-8"))

        client_public_key_path = self._get_pyop_provider_client_secret_path(
            authorize_state["client_id"]
        )
        client_public_key = load_jwk(client_public_key_path)

        userinfo = self._jwt_service.create_jwe(
            client_public_key, {"signed_userinfo": signed_userinfo}
        )

        # authorize client
        pyop_authorize_request = self._pyop_provider.parse_authentication_request(
            urlencode(authorize_state), request.headers
        )
        authorize_response = self._pyop_provider.authorize(pyop_authorize_request, "_")
        # sub = self._pyop_provider.authz_state.get_subject_identifier("public", "_")
        # print(sub)
        # access_token: AccessToken = self._pyop_provider.authz_state.create_access_token(
        #     AuthorizationRequest(**authorize_state), sub, user_info=userinfo)
        # access_token = secrets.token_urlsafe(96)[:64]

        self._redis_client.set("userinfo_" + authorize_response["code"], userinfo)

        # code = secrets.token_urlsafe(96)[:64]
        # self._redis_client.set("access_token_" + authorize_response["code"], access_token)

        redirect_url = (
            authorize_state["redirect_uri"]
            + "?"
            + urlencode({"state": authorize_state["state"], "code": authorize_response["code"]})
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
        test_token_response = self._pyop_provider.handle_token_request(token_request.query_string, request.headers)
        userinfo = self._redis_client.get("userinfo_" + token_request.code)
        self._redis_client.delete("userinfo_" + token_request.code)
        self._redis_client.set("userinfo_" + test_token_response["access_token"], userinfo)
        print("token response: \n", test_token_response)

        return test_token_response
        # access_token = self._redis_client.get("access_token_" + token_request.code)
        # if access_token is None:
        #     raise RuntimeError("Invalid code")
        #
        # client_public_key_path = self._get_pyop_provider_client_secret_path(
        #     token_request.client_id
        # )
        # client_public_key = load_jwk(client_public_key_path)
        #
        # id_token = self._jwt_service.create_jwe(client_public_key, {})
        # return JSONResponse(
        #     {
        #         "access_token": access_token.decode("utf-8"),
        #         "id_token": id_token,
        #         "token_type": "Bearer",
        #         "expires_in": 60 * 5,
        #     }
        # )

    def userinfo(self, request: Request) -> Response:
        access_token = request.headers["Authorization"].split(" ")[1]
        print("from userinfo request:\n", access_token)
        userinfo = self._redis_client.get("userinfo_" + access_token)
        return Response(content=userinfo, media_type="application/jwt")

    def get_jwks(self) -> JSONResponse:
        return JSONResponse(content=jsonable_encoder(self._pyop_provider.jwks))

    def get_well_known_openid_config(self) -> JSONResponse:
        return JSONResponse(
            jsonable_encoder(self._pyop_provider.configuration_information)
        )

    def _get_pyop_provider_client_secret_path(self, client_id: str) -> str:
        # Acts like a get data from database
        client = self._pyop_provider.clients[client_id]
        return client["client_public_key_path"]
