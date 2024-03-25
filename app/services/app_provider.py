from typing import Any, Optional, Dict

from urllib.parse import urlencode
import logging

from starlette.datastructures import Headers
from oic.oic.message import AuthorizationResponse

from pyop.provider import Provider
from pyop.authz_state import AuthorizationState
from pyop.access_token import extract_bearer_token_from_http_request  # type: ignore
from pyop.exceptions import BearerTokenError  # type: ignore

from jwkest.jwk import RSAKey
from jwcrypto.jwk import JWK

from app.utils import load_jwk
from app.models.authorize_request import AuthorizeRequest

logger = logging.getLogger(__name__)


class AppProvider(Provider):
    # pylint: disable=useless-parent-delegation
    def __init__(  # type: ignore
        self,
        signing_key: RSAKey,
        configuration_information,
        authz_state: AuthorizationState,
        clients,
        userinfo,
        *,
        id_token_lifetime=3600,
        extra_scopes=None,
    ):
        super().__init__(
            signing_key,
            configuration_information,
            authz_state,
            clients,
            userinfo,
            id_token_lifetime=id_token_lifetime,
            extra_scopes=extra_scopes,
        )

    def authorize_client(
        self, authorize_request: AuthorizeRequest, headers: Headers
    ) -> AuthorizationResponse:
        """
        Wrapper method to handle pyop authorization. The client id is an placeholder
        """
        pyop_authorization_request = self.parse_authentication_request(
            urlencode(authorize_request), headers  # type: ignore
        )
        return self.authorize(pyop_authorization_request, "_")

    def extract_bearer_token_from_http_request(
        self, parsed_request: Optional[Any] = None, authz_header: Optional[Any] = None
    ) -> Optional[str]:
        """
        wrapper method for pyop extract bearer token from http request
        """
        try:
            return extract_bearer_token_from_http_request(parsed_request, authz_header)
        except BearerTokenError as _e:
            logger.exception(_e)
            return None

    def introspect_access_token(self, access_token: str) -> bool:
        """
        wrapper method that inspects access token is active and returns a bool from pyop_introspect_access_token
        """
        introspection: Dict[str, bool] = self.authz_state.introspect_access_token(
            access_token
        )
        return introspection["active"]

    def get_client_public_key(self, client_id: str) -> JWK:
        client = self.clients[client_id]
        return load_jwk(client["client_public_key_path"])
