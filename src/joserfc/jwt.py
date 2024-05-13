import json
import typing as t
from .rfc7519.claims import Claims, convert_claims, check_sensitive_data
from .rfc7519.registry import ClaimsOption, JWTClaimsRegistry
from .jws import (
    JWSRegistry,
    serialize_compact,
    deserialize_compact,
)
from .jwe import (
    JWERegistry,
    encrypt_compact,
    decrypt_compact,
)
from .jwk import KeyFlexible
from .errors import InvalidTypeError, InvalidPayloadError
from .util import to_bytes
from .registry import Header

__all__ = [
    "Claims",
    "Token",
    "ClaimsOption",
    "JWTClaimsRegistry",
    "encode",
    "decode",
    "check_sensitive_data",
]

JWTRegistry = t.Union[JWSRegistry, JWERegistry]


class Token:
    """The extracted token object, which contains ``header`` and ``claims``.

    :param header: the header part of the JWT
    :param claims: the payload part of the JWT
    """
    def __init__(self, header: Header, claims: Claims):
        #: header in dict
        self.header = header
        #: payload claims in dict
        self.claims = claims


def encode(
        header: Header,
        claims: Claims,
        key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWTRegistry] = None) -> str:
    """Encode a JSON Web Token with the given header, and claims.

    :param header: A dict of the JWT header
    :param claims: A dict of the JWT claims to be encoded
    :param key: key used to sign the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a ``JWSRegistry`` or ``JWERegistry`` to use
    """
    # add ``typ`` in header
    _header = {"typ": "JWT", **header}
    payload = convert_claims(claims)
    if isinstance(registry, JWERegistry):
        return encrypt_compact(_header, payload, key, algorithms, registry)
    else:
        return serialize_compact(_header, payload, key, algorithms, registry)


def decode(
        value: t.Union[bytes, str],
        key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWTRegistry] = None) -> Token:
    """Decode the JSON Web Token string with the given key, and validate
    it with the claims requests.

    :param value: text of the JWT
    :param key: key used to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a ``JWSRegistry`` or ``JWERegistry`` to use
    :raise: BadSignatureError
    """
    _value = to_bytes(value)
    header: Header
    payload: bytes
    if isinstance(registry, JWERegistry):
        header, payload = _decode_jwe(_value, key, algorithms, registry)
    else:
        header, payload = _decode_jws(_value, key, algorithms, registry)

    try:
        claims: Claims = json.loads(payload)
    except (TypeError, ValueError):
        raise InvalidPayloadError()

    token = Token(header, claims)
    typ = token.header.get("typ")
    # https://www.rfc-editor.org/rfc/rfc7519#section-5.1
    # If present, it is RECOMMENDED that its value be "JWT".
    if typ and typ != "JWT":
        raise InvalidTypeError()
    return token


def _decode_jwe(
        value: bytes,
        key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None) -> t.Tuple[Header, bytes]:
    jwe_obj = decrypt_compact(value, key, algorithms, registry)
    assert jwe_obj.plaintext is not None
    return jwe_obj.headers(), jwe_obj.plaintext


def _decode_jws(
        value: bytes,
        key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None) -> t.Tuple[Header, bytes]:
    jws_obj = deserialize_compact(value, key, algorithms, registry)
    assert jws_obj.payload is not None
    return jws_obj.headers(), jws_obj.payload
