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

templates = Jinja2Templates(directory="jinja2")


class OidcService:
    def __init__(self, redis_client: Redis, jwt_service: JwtService):
        self._redis_client = redis_client
        self._jwt_service = jwt_service

    def authorize(
        self,
        request: Request,
        redirect_uri: str,
        state: str,
    ):
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
        # return HTMLResponse(file_content_raise_if_none("static/login.html"))

    def submit(
        self,
        uzi_number: str,
        state: str,
    ):
        authorize_state = self._redis_client.get("authorize_" + state)
        if authorize_state is None:
            raise RuntimeError("Invalid state")
        authorize_state = json.loads(authorize_state.decode("utf-8"))

        resp = requests.get(
            "http://localhost:8002/signed-uzi?uzi_number=" + uzi_number, timeout=30
        )
        if resp.status_code != 200:
            raise RuntimeError("Unable to fetch uzi number")
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

    def token(self, code: str):
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

    def userinfo(self, request: Request):
        access_token = request.headers["Authorization"].split(" ")[1]
        userinfo = self._redis_client.get("userinfo_" + access_token)
        return Response(content=userinfo, media_type="application/jwt")
