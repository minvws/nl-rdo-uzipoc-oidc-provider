from configparser import ConfigParser

from app.services.jwt_service import JwtService
from app.services.oidc_service import OidcService
from app.storage.redis.redis_client import create_redis_client
from app.utils import load_jwk, file_content_raise_if_none, kid_from_certificate

config = ConfigParser()
config.read("app.conf")

register_base_url = config.get("app", "register_base_url")

jwt_priv_key = load_jwk(config.get("app", "jwt_priv_key_path"))
# TODO GB: Moet eruit
jwt_pub_key = load_jwk(config.get("app", "jwt_pub_key_path"))

jwt_crt_content = file_content_raise_if_none(config.get("app", "jwt_crt_path"))

_redis_client = create_redis_client(config["redis"])


####
## Services
####
jwt_service_ = JwtService(
    jwt_priv_key=jwt_priv_key,
    crt_kid=kid_from_certificate(jwt_crt_content),
)

oidc_service_ = OidcService(
    redis_client=_redis_client,
    jwt_service=jwt_service_,
    register_base_url=register_base_url,
)
