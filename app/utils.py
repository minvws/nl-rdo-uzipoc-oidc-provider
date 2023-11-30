import base64
import secrets
from os import path
from typing import Union, Any, List
import json
from Cryptodome.Hash import SHA256
from Cryptodome.IO import PEM
from jwcrypto.jwk import JWK
from jwkest.jwk import RSAKey, import_rsa_key


def load_jwk(filepath: str) -> JWK:
    with open(filepath, encoding="utf-8") as file:
        return JWK.from_pem(file.read().encode("utf-8"))


def file_content_raise_if_none(filepath: str) -> str:
    optional_file_content = file_content(filepath)
    if optional_file_content is None:
        raise ValueError(f"file_content for {filepath} shouldn't be None")
    return optional_file_content


def file_content(filepath: str) -> Union[str, None]:
    if filepath is not None and path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as file:
            return file.read()
    return None


def kid_from_certificate(certificate: str) -> str:
    der = PEM.decode(certificate)
    sha = SHA256.new()
    sha.update(der[0])
    return base64.b64encode(sha.digest()).decode("utf-8")


def load_rsa_key_from_path(signing_key_path: str, signing_key_crt_path: str) -> RSAKey:
    signing_key = file_content_raise_if_none(signing_key_path)
    signing_key_crt = file_content_raise_if_none(signing_key_crt_path)
    kid = kid_from_certificate(signing_key_crt)
    key = RSAKey(key=import_rsa_key(signing_key), alg="RS256")
    key.kid = kid
    return key


def pyop_configuration_information_callable(
    issuer: str,
    authorize_endpoint: str,
    jwks_endpoint: str,
    token_endpoint: str,
    userinfo_endpoint: str,
    scopes_supported: List[str],
) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": issuer + authorize_endpoint,
        "jwks_uri": issuer + jwks_endpoint,
        "token_endpoint": issuer + token_endpoint,
        "scopes_supported": scopes_supported,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["pairwise"],
        "token_endpoint_auth_methods_supported": ["none"],
        "claims_parameter_supported": True,
        "userinfo_endpoint": issuer + userinfo_endpoint,
    }


def rand_pass(size: int) -> str:
    return secrets.token_urlsafe(size)


def json_from_file(filepath: str) -> Any:
    return json.loads(file_content_raise_if_none(filepath))
