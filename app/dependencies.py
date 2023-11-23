from configparser import ConfigParser

from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from pyop.provider import Provider
from pyop.authz_state import AuthorizationState
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo
from app.storage.redis.redis_client import create_redis_client
from app.utils import (
    load_jwk,
    file_content_raise_if_none,
    kid_from_certificate,
    json_from_file,
    pyop_rsa_signing_key_callable,
    pyop_configuration_information_callable,
)

config = ConfigParser()
config.read("app.conf")

register_base_url = config.get("app", "register_base_url")

jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))

jwt_crt_content = file_content_raise_if_none(config.get("app", "jwt_crt_path"))

_redis_client = create_redis_client(config["redis"])

identities = json_from_file(config.get("app", "identities_path"))

mock_jwks_path = config.get("app", "mock_jwks_path")  # to be removed

# signing keys
signing_key = config.get("secrets", "rsa_private_key")
signing_key_cert = config.get("secrets", "rsa_private_key_crt")

# PyOP OIDC Provider Config
issuer = config.get("oidc", "issuer")
authorization_endpoint = config.get("oidc", "authorization_endpoint")
jwks_endpoint = config.get("oidc", "jwks_uri")
token_endpoint = config.get("oidc", "token_endpoint")
userinfo_endpoint = config.get("oidc", "userinfo_endpoint")
scopes_supported = [config.get("oidc", "scopes_supported")]
sub_hash_salt = config.get("oidc", "subject_id_hash_salt")

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory)

####
## Services
####
jwt_service_ = JwtService(
    jwt_priv_key=jwt_priv_key,
    crt_kid=kid_from_certificate(jwt_crt_content),
)

pyop_provider = Provider(
    signing_key=pyop_rsa_signing_key_callable(signing_key, signing_key_cert),
    configuration_information=pyop_configuration_information_callable(
        issuer,
        authorization_endpoint,
        jwks_endpoint,
        token_endpoint,
        userinfo_endpoint,
        scopes_supported,
    ),
    clients={"37692967-0a74-4e91-85ec-a4250e7ad5e8"},
    authz_state=authz_state,
    userinfo=Userinfo({"_": {}})
)

oidc_service_ = OidcService(
    redis_client=_redis_client,
    jwt_service=jwt_service_,
    register_base_url=register_base_url,
    identities=identities,
    pyop_provider=pyop_provider,
    mock_jwks=json_from_file(mock_jwks_path),
)
