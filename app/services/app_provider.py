from pyop.provider import Provider
from pyop.authz_state import AuthorizationState

from jwkest.jwk import RSAKey


class AppProvider(Provider):

    def __init__(
            self,
            signing_key: RSAKey,
            configuration_information,
            authz_state: AuthorizationState,
            clients,
            userinfo,
            *,
            id_token_lifetime=3600,
            extra_scopes=None,
            # trusted_certificates_directory=None,
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