import json
import secrets
from urllib.parse import urlencode
from fastapi import Request

import requests
from redis import Redis
from starlette.responses import RedirectResponse, JSONResponse, Response
from starlette.templating import Jinja2Templates

from app.services.jwt_service import JwtService
from app.utils import rand_pass

from typing import Dict

templates = Jinja2Templates(directory="jinja2")


class OidcService:
    def __init__(
        self, redis_client: Redis, jwt_service: JwtService, register_base_url: str, 
        oidc_providers: Dict[str, str]
    ):
        self._redis_client = redis_client
        self._jwt_service = jwt_service
        self._register_base_url = register_base_url
        self._oidc_providers = oidc_providers

    def authorize(
        self,
        request: Request,
        redirect_uri: str,
        state: str,
    ) -> Response:
        session_key = rand_pass(100)
        authorize_state = {"redirect_uri": redirect_uri, "state": state}
        self._redis_client.set("authorize_" + session_key, json.dumps(authorize_state))

        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "state": session_key,
            },
        )

    def submit(
        self,
        uzi_number: str,
        state: str,
    ) -> Response:
        authorize_state = self._redis_client.get("authorize_" + state)
        if authorize_state is None:
            raise RuntimeError("Invalid state")
        authorize_state = json.loads(authorize_state.decode("utf-8"))

        resp = requests.get(
            self._register_base_url + "/signed-uzi?uzi_number=" + uzi_number, timeout=30
        )
        if resp.status_code != 200:
            raise RuntimeError("Unable to fetch uzi number")
        ## TODO: Update to JWE
        userinfo = self._jwt_service.create_jwt(
            {"signed_uzi_number": resp.json()["signed_uzi_number"]}
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
        return RedirectResponse(redirect_url)

    def token(self, code: str) -> Response:
        access_token = self._redis_client.get("access_token_" + code)
        if access_token is None:
            raise RuntimeError("Invalid code")
        id_token = self._jwt_service.create_jwt({})
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
    
    def get_providers(self,):
        return JSONResponse(self._oidc_providers)
    
    def get_all_providers_well_known_openid_config(self):
        openid_config = {}
        for key, value in self._oidc_providers.items():
            data = self._get_oidc_provider_wellknown_config(value)
            openid_config[key] = data
        
        return JSONResponse(openid_config)


    
    def _get_oidc_provider_wellknown_config(self, url: str):
        well_known_config = requests.get(url).json()
        return well_known_config
