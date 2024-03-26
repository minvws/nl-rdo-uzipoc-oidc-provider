from configparser import ConfigParser
from pyop.authz_state import AuthorizationState
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from app.constants import (
    AUTHORIZATION_ENDPOINT,
    JWKS_ENDPOINT,
    TOKEN_ENDPOINT,
    USERINFO_ENDPOINT,
)
from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.services.template_service import TemplateService
from app.services.app_provider import AppProvider
from app.services.vite_manifest_service import ViteManifestService
from app.storage.redis.redis_client import create_redis_client
from app.utils import (
    load_jwk,
    file_content_raise_if_none,
    kid_from_certificate,
    json_from_file,
    load_rsa_key_from_path,
    pyop_configuration_information_callable,
)

config = ConfigParser()
config.read("app.conf")

register_base_url = config.get("app", "register_base_url")

jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))

jwt_crt_content = file_content_raise_if_none(config.get("app", "jwt_crt_path"))

_redis_client = create_redis_client(config["redis"])

identities = json_from_file(config.get("app", "identities_path"))

# signing keys
signing_key = config.get("app", "rsa_private_key")
signing_key_cert = config.get("app", "rsa_private_key_crt")

# PyOP OIDC Provider Config
issuer = config.get("oidc", "issuer")
scopes_supported = config.get("oidc", "scopes_supported").split(" ")
sub_hash_salt = config.get("oidc", "subject_id_hash_salt")

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory)
clients = json_from_file(config.get("app", "clients_path"))

# Templates config
vite_manifest = json_from_file(config.get("templates", "vite_manifest_path"))
templates_directory = config.get("templates", "jinja_path")

####
## Services
####
vite_manifest_service = ViteManifestService(
    manifest=vite_manifest,
)

template_service = TemplateService(
    jinja_template_directory=templates_directory,
    vite_manifest_service=vite_manifest_service,
)

jwt_service_ = JwtService(
    jwt_priv_key=jwt_priv_key,
    crt_kid=kid_from_certificate(jwt_crt_content),
)

pyop_provider = AppProvider(
    signing_key=load_rsa_key_from_path(signing_key, signing_key_cert),
    configuration_information=pyop_configuration_information_callable(
        issuer,
        AUTHORIZATION_ENDPOINT,
        JWKS_ENDPOINT,
        TOKEN_ENDPOINT,
        USERINFO_ENDPOINT,
        scopes_supported,
    ),
    clients=clients,
    authz_state=authz_state,
    userinfo=Userinfo({"_": {}}),
)

oidc_service_ = OidcService(
    redis_client=_redis_client,
    jwt_service=jwt_service_,
    register_base_url=register_base_url,
    identities=identities,
    pyop_provider=pyop_provider,
    template_service=template_service,
    identities_page_sidebar_template=config.get(
        "templates", "identities_page_sidebar_template", fallback=None
    ),
)
