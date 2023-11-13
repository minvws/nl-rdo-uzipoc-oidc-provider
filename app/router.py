from fastapi import APIRouter, Depends, Request
from fastapi import Form
from fastapi.responses import Response

from app.dependencies import oidc_service_

from app.services.oidc_service import OidcService

import requests

router = APIRouter()


@router.get("/authorize")
async def authorize(
    request: Request,
    redirect_uri: str,
    state: str,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.authorize(request, redirect_uri, state)


@router.get("/submit")
async def submit(
    uzi_number: str,
    state: str,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.submit(uzi_number, state)


@router.post("/token")
async def token(
    code: str = Form(...),
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.token(code)


@router.get("/userinfo")
async def userinfo(
    request: Request,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.userinfo(request)


@router.get("/providers/all")
async def get_providers_list(
    oidc_service: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service.get_providers()


@router.get("/providers/all/.well-known/openid-configuration")
async def hello(oidc_service: OidcService = Depends(lambda: oidc_service_)) -> Response:
    return oidc_service.get_all_providers_well_known_openid_config()
