import json
import secrets
from typing import Dict, Optional
from urllib.parse import urlencode
from fastapi import Request
from fastapi.encoders import jsonable_encoder
from pyop.provider import Provider as PyopProvider

import requests
from redis import Redis
from starlette.responses import JSONResponse, Response, RedirectResponse

from app.services.jwt_service import JwtService
from app.services.template_service import TemplateService
from app.utils import rand_pass, load_jwk


class OidcService:
    def __init__(
        self,
        redis_client: Redis,
        jwt_service: JwtService,
        register_base_url: str,
        identities: Dict[str, str],
        pyop_provider: PyopProvider,
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
        self, request: Request, redirect_uri: str, state: str, scope: str
    ) -> Response:
        scopes = scope.split(" ")
        session_key = rand_pass(100)
        authorize_state = {"redirect_uri": redirect_uri, "state": state}

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

    def submit(
        self,
        bsn: str,
        state: str,
    ) -> Response:
        authorize_state = self._redis_client.get("authorize_" + state)
        if authorize_state is None:
            raise RuntimeError("Invalid state")
        authorize_state = json.loads(authorize_state.decode("utf-8"))
        print(authorize_state)
        resp = requests.get(
            self._register_base_url + "/signed-userinfo?bsn=" + bsn,
            timeout=30,
        )
        if resp.status_code != 200:
            return RedirectResponse(authorize_state["redirect_uri"], status_code=400,)

        client_public_key_path = self._get_pyop_provider_client_secret_path()
        client_public_key = load_jwk(client_public_key_path)

        userinfo = self._jwt_service.create_jwe(
            client_public_key, {"signed_userinfo": resp.json()["signed_userinfo"]}
        )
        access_token = secrets.token_urlsafe(96)[:64]
        self._redis_client.set("userinfo_" + access_token, userinfo)

        code = secrets.token_urlsafe(96)[:64]
        self._redis_client.set("access_token_" + code, access_token)

        redirect_url = (
            authorize_state["redirect_uri"]
            + "?"
            + urlencode({"state": authorize_state["state"], "code": code})
        )
        return Response(json.dumps({"redirect_url": redirect_url}))

    def token(self, code: str) -> Response:
        access_token = self._redis_client.get("access_token_" + code)
        if access_token is None:
            raise RuntimeError("Invalid code")

        client_public_key_path = self._get_pyop_provider_client_secret_path()
        client_public_key = load_jwk(client_public_key_path)

        id_token = self._jwt_service.create_jwe(client_public_key, {})
        return JSONResponse(
            {
                "access_token": access_token.decode("utf-8"),
                "id_token": id_token,
                "token_type": "Bearer",
                "expires_in": 60 * 5,
            }
        )

    def userinfo(self, request: Request) -> Response:
        access_token = request.headers["Authorization"].split(" ")[1]
        userinfo = self._redis_client.get("userinfo_" + access_token)
        return Response(content=userinfo, media_type="application/jwt")

    def get_jwks(self) -> JSONResponse:
        return JSONResponse(content=jsonable_encoder(self._pyop_provider.jwks))

    def get_well_known_openid_config(self) -> JSONResponse:
        return JSONResponse(
            jsonable_encoder(self._pyop_provider.configuration_information)
        )

    def _get_pyop_provider_client_secret_path(self) -> str:
        # Acts like a get data from database
        clients = self._pyop_provider.clients[0]
        return clients["client_public_key_path"]
