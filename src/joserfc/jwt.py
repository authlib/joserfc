import typing as t
from .rfc7519.claims import Claims, convert_claims, check_sensitive_data
from .rfc7519.registry import ClaimsOption, JWTClaimsRegistry
from .jws import (
    JWSRegistry,
    CompactSignature,
    serialize_compact,
    validate_compact as validate_jws,
    extract_compact as extract_jws,
)
from .jwe import (
    JWERegistry,
    CompactEncryption,
    encrypt_compact,
    validate_compact as validate_jwe,
    extract_compact as extract_jwe,
)
from .jwk import KeyFlexible
from .errors import InvalidTypeError, InvalidPayloadError
from .util import to_bytes
from .registry import Header

__all__ = [
    "Header",
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
        self.header = header
        self.claims = claims

    def __repr__(self):
        return str(self.claims)


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
    header["typ"] = "JWT"
    payload = convert_claims(claims)
    if "enc" in header:
        result = encrypt_compact(header, payload, key, algorithms, registry)
    else:
        result = serialize_compact(header, payload, key, algorithms, registry)
    return result.decode("utf-8")


def extract(value: t.AnyStr) -> Token:
    """Extract the JSON Web Token string, without validating with the key,
    without validating the header and claims."""
    obj = _extract_segment(value)
    return Token(obj.headers(), obj.claims)


def decode(
        value: t.AnyStr,
        key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWTRegistry] = None) -> Token:
    """Decode the JSON Web Token string with the given key, and validate
    it with the claims requests. This method is a combination of the
    :function:`extract` and :function:`validate`.

    :param value: text of the JWT
    :param key: key used to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a ``JWSRegistry`` or ``JWERegistry`` to use
    :raise: BadSignatureError
    """
    obj = _extract_segment(value)

    token = Token(obj.headers(), obj.claims)
    typ = token.header.get("typ")
    # https://www.rfc-editor.org/rfc/rfc7519#section-5.1
    # If present, it is RECOMMENDED that its value be "JWT".
    if typ and typ != "JWT":
        raise InvalidTypeError()

    if isinstance(obj, CompactSignature):
        validate_jws(obj, key, algorithms=algorithms, registry=registry)
    else:
        validate_jwe(obj, key, algorithms=algorithms, registry=registry)
    return token


def _extract_segment(value: t.AnyStr) -> t.Union[CompactSignature, CompactEncryption]:
    segment = to_bytes(value)
    if segment.count(b".") == 4:
        obj = extract_jwe(segment)
    else:
        obj = extract_jws(segment)

    try:
        assert isinstance(obj.claims, dict)
    except (ValueError, TypeError):
        raise InvalidPayloadError("Payload should be a JSON dict")
    return obj
