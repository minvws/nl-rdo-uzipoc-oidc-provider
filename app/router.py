from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi import Form
from fastapi.responses import Response

from app.dependencies import oidc_service_
from app.models.authorize_request import AuthorizeRequest
from app.services.oidc_service import OidcService

router = APIRouter()


@router.get("/authorize")
async def authorize(
    request: Request,
    authrize_request: AuthorizeRequest = Depends(),
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.authorize(request, authrize_request)


@router.post("/submit")
async def submit(
    request: Request,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    posted = await request.json()
    return oidc_service.handle_submit(posted)


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
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.get_well_known_openid_config()


@router.get("/jwks")
async def get_jwks_keys(
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.get_jwks()


@router.get("/signed-userinfo")
async def get_signed_userinfo(
    bsn: str,
    userinfo_validity_in_seconds: Optional[str] = None,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.get_userinfo_token_from_register(
        bsn, userinfo_validity_in_seconds
    )
