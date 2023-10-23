import textwrap
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi import Form

from app.dependencies import oidc_service_
from app.models.submit import Submit

from app.services.oidc_service import OidcService

router = APIRouter()


@router.get("/authorize")
async def authorize(
    request: Request,
    redirect_uri: str,
    state: str,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service.authorize(request, redirect_uri, state)


@router.get("/submit")
async def submit(
        request: Request,
        uziNumber: str,
        state: str,
        oidc_service: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service.submit(request, uziNumber, state)


@router.post("/token")
async def token(
        request: Request,
        code: str = Form(...),
        oidc_service: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service.token(request, code)


@router.get("/userinfo")
async def userinfo(
        request: Request,
        oidc_service: OidcService = Depends(lambda: oidc_service_),
):
    return oidc_service.userinfo(request)

