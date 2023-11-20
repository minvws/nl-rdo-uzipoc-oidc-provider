import json
import secrets
from urllib.parse import urlencode
from fastapi import Request

import requests
from redis import Redis
from starlette.responses import JSONResponse, Response
from starlette.templating import Jinja2Templates

from app.services.jwt_service import JwtService
from app.utils import rand_pass

from typing import Dict

templates = Jinja2Templates(directory="jinja2")


class OidcService:
    def __init__(
        self,
        redis_client: Redis,
        jwt_service: JwtService,
        register_base_url: str,
        oidc_providers: Dict[str, str],
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
        return Response(json.dumps({"redirect_url": redirect_url}))

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

    def get_providers(
        self,
    ):
        return JSONResponse(self._oidc_providers)

    # async def get_all_providers_well_known_openid_config(self):
    #     openid_config = {}
    #     for provider, url in self._oidc_providers.items():
    #         data = await self._get_oidc_provider_wellknown_config(url)
    #         openid_config[provider] = data

    #     return JSONResponse(openid_config)

    # async def _get_oidc_provider_wellknown_config(self, url: str):
    #     well_known_config = requests.get(url, verify=False).json()
    #     return well_known_config

    def get_jwks(self) -> JSONResponse:
        """
        mock jwks
        """
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "7f2zIdJR9++ogddXXWJpGpxSctKTzBYw0LidM4ALjOc=",
                    "alg": "RS256",
                    "e": "AQAB",
                    "n": "rVVoVcph1FD6ClrccuRvFKuz0DP9qzW7WsMGA1QMSgv2K0tnxWzn-1g4dO5LhdVESn-Lyq8TzmOOVyPyTce5XPMJ6aJLSoq13uOrbONRsf1d_ZU0G_DlZE4pCWtACkAa7XtzZyf42hQwHGaxZVLrgggQIKZ31H-Sp2mDRG4WpXHDq6hXwuZt82gVXFxiCO5u4kYDGesNgawSd7xCaMAkJNd_o274ci2eEfN5JDd0u6au2pO13BYhECKtvU3_OH0btrUUWoQ2fDkNEYNRQ4ffPf1CYCAS5OXzIVfhN_nGlvooECU35Cs4WGWfCMBUPYbxbrL2B9lokyuzkGYcZcTD8m4PN_IE0583alzFwvmzqi28ET6wnbeEaGxyb2IQsZahJMtzf016hWwZQfmq1q1kkHeL7mPVN5zJvfUSNnJKvuA3L99RbPA1cHmAsGpHYLWPn3mXAZzdey8BDyTdWD2r_4lGTR2cCddOLBb5aVfWkSqBspi30T6ftW5BJVTEqda1TdIJ5Rh0_aYnGf1En5xemvayxDqd0JG5rB8-CPZ-4z2Ld-pZ1bK1yhnSEa_HbYn5uXboSgtCHrfkrSfKtjVdT3zaO0pW8unHG7I-pG6pjpQSXzL2uTiiQm7W-Wd264QQnPsL62EAXR1s6GM0zOT9BoKYBCjhVT0xBPYrhzp6eqk",
                },
                {
                    "kty": "RSA",
                    "n": "lVhvfWwLy0tRx9i4nxvV64JacRW9XwD6jKJF19A6uAa0sb7t38D6SawgUZycWD4kU0kJwQO6TtoWffUSFmJwdQKRLfVfSV18sMcUhIw2jRIQ4XdT7MTHSqgZuE0-FGStR0ifH327FSRGpemqy3oxEN_pSMl8KI5bgHPrMa2HDOvCNiPT9edXzxa-JNCsKYxmEg7RyXNl23CnKSYVYJWN1RPL4FDfo8xn18d3_2vTBxW9YEyj--bndf3B4xgRUPLuVFN6AKROrV9QHicJy8vi3UTCTuGLd0itUGTtjzshX0Du717Izkrq4GXGoSCtSRi-S5kdFLNKRSgm2UVXbpYaXw",
                    "e": "AQAB",
                    "kid": "76Imq71Z8xnO/eh/kFLfaIV5zlboqRSyJnHdkPaJx48=",
                },
                {
                    "kty": "RSA",
                    "n": "jrEaIPOeFmR9ZEoBS-M73wFbp5KIoEjce9uDQ_w41cuRlM8YoCxDZoW7cA9qatClLGG3Fb9A-J0Vdfm0q5umrTxVOmjiSezK4L_AUzm7Q6iTq_MfFs4LmKcu9XSCy7N4OQeuWsDc1Vpk4G4v3umR8vIeNeoIxYP4XxaQtQ8kxli61GZqLETlc5xxAOXtoUKr8XhnwFsgSNEOAoh5zex3rmz7V0qKQY9wLw20Pd1K0h9j4q2vAzivdR6pbY98XL7NLELSFn0M_l_arir8OhB9gNCJiTtqtjkdGHUTahVMwECdTi4ZEuf5nS_2kCCUsVOHugR6PUQQyLSuy0nLvJ50jw",
                    "e": "AQAB",
                    "kid": "Ohb7BwgSKk1hYPSCNnRmT/Qfw3NBK6R7y4NvdHIdp0k=",
                },
                {
                    "kty": "RSA",
                    "n": "rsO9aaPvMpY4AVev_Dnsp5EisnWcuvLsscQTTrKzzHAxLu_QKluJsuWskzlRpMmNc9Ywqwa5FlF_JsjlBxUP3hU4K7URkSdjjIrrqzMhnjYPeKb7tHZQcNjeOGj28n11e6Md4r9ZeFEuVLzeRkWE86U0Z8pbELlEerBpS2_1ti2srbQPYh_YZvnwof_cGdv_livBY7Xp0MnZy1Lm-FKGVsolEQ06E3B3zlZHTGaxCIPazU6W_HWpz41A72yDd4jBRcplNpDLIWQgCi_O_uNJ1K-FaT6MX98HsAI8Wp9gWMHZ6ebP3YKMgpAHbiHLvs1dawzGmeKANFuygFuC79clqw",
                    "e": "AQAB",
                    "kid": "erXru7XhFaNxsU+DTHne1Pz0mUh41L2I2IhtIVzYW34=",
                },
            ]
        }
        return JSONResponse(jwks)

    def get_well_known_openid_config(self) -> JSONResponse:
        openid_well_known_config = {
            "issuer": "http://localhost:8003",
            "authorize_endpoint": "http://localhost:8003/authorize",
            "token_endpoint": "http://localhost:8003/token",
            "userinfo_endpoint": "http://localhost:8003/userinfo",
            "jwks_uri": "http://localhost:8003/jwks",
            "scopes_supported": ["openid", "uzi"],
        }
        return JSONResponse(openid_well_known_config)
