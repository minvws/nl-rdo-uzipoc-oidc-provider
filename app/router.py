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
    scope: str,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    return oidc_service.authorize(request, redirect_uri, state, scope)


@router.post("/submit")
async def submit(
    request: Request,
    oidc_service: OidcService = Depends(lambda: oidc_service_),
) -> Response:
    posted = await request.json()
    if "uzi_id" not in posted or "state" not in posted:
        return Response(status_code=400)
    uzi_id = posted["uzi_id"]
    state = posted["state"]
    return oidc_service.submit(uzi_id, state)


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
