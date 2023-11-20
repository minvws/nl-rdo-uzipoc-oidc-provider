from fastapi import APIRouter, Depends, Request
from fastapi import Form
from fastapi.responses import Response

from app.dependencies import oidc_service_

from app.services.oidc_service import OidcService

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


@router.get("/.well-known/openid-configuration")
async def get_openid_well_known_config(
    oidc_service_: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service_.get_well_known_openid_config()


@router.get("/jwks")
async def get_jwks_keys(oidc_service_: OidcService = Depends(lambda: oidc_service_)):
    return oidc_service_.get_jwks()
