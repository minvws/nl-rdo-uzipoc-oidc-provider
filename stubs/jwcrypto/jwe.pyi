# mypy: disallow_untyped_defs=False

from _typeshed import Incomplete
from jwcrypto import common as common
from jwcrypto.common import JWException as JWException, JWKeyNotFound as JWKeyNotFound, JWSEHeaderParameter as JWSEHeaderParameter, JWSEHeaderRegistry as JWSEHeaderRegistry, base64url_decode as base64url_decode, base64url_encode as base64url_encode, json_decode as json_decode, json_encode as json_encode
from jwcrypto.jwa import JWA as JWA
from jwcrypto.jwk import JWKSet as JWKSet

JWEHeaderRegistry: Incomplete
default_allowed_algs: Incomplete

class InvalidJWEData(JWException):
    def __init__(self, message: Incomplete | None = ..., exception: Incomplete | None = ...) -> None: ...
InvalidCEKeyLength = common.InvalidCEKeyLength
InvalidJWEKeyLength = common.InvalidJWEKeyLength
InvalidJWEKeyType = common.InvalidJWEKeyType
InvalidJWEOperation = common.InvalidJWEOperation

class JWE:
    objects: Incomplete
    plaintext: Incomplete
    header_registry: Incomplete
    cek: Incomplete
    decryptlog: Incomplete
    def __init__(self, plaintext: Incomplete | None = ..., protected: Incomplete | None = ..., unprotected: Incomplete | None = ..., aad: Incomplete | None = ..., algs: Incomplete | None = ..., recipient: Incomplete | None = ..., header: Incomplete | None = ..., header_registry: Incomplete | None = ...) -> None: ...
    @property
    def allowed_algs(self): ...
    @allowed_algs.setter
    def allowed_algs(self, algs) -> None: ...
    def add_recipient(self, key, header: Incomplete | None = ...) -> None: ...
    def serialize(self, compact: bool = ...): ...
    def decrypt(self, key) -> None: ...
    def deserialize(self, raw_jwe, key: Incomplete | None = ...) -> None: ...
    @property
    def payload(self): ...
    @property
    def jose_header(self): ...
    @classmethod
    def from_jose_token(cls, token): ...
    def __eq__(self, other): ...
