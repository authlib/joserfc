from typing import Optional, AnyStr
from .rfc7515.compact import extract_compact
from .rfc7519.claims import Claims, convert_claims
from .rfc7519.validators import ClaimsOption, JWTClaimsRequests
from .rfc7519.registry import JWTRegistry, default_registry
from .jws import serialize_compact, validate_compact
from .jwk import KeyFlexible
from .errors import InvalidTypeError, InvalidPayloadError
from .util import to_bytes
from .registry import Header


__all__ = [
    'Header',
    'Claims',
    'Token',
    'ClaimsOption',
    'JWTRegistry',
    'JWTClaimsRequests',
    'encode',
    'decode',
]


class Token:
    def __init__(self, header: Header, claims: Claims):
        self.header = header
        self.claims = claims


def encode(
        header: Header,
        claims: Claims,
        key: KeyFlexible,
        registry: Optional[JWTRegistry]=None) -> str:
    """Encode a JSON Web Token with the given header, and claims.

    :param header: A dict of the JWT header
    :param claims: A dict of the JWT claims to be encoded
    :param key: key used to sign the signature
    :param registry: a JWTRegistry to use
    """
    # add ``typ`` in header
    header['typ'] = 'JWT'
    payload = convert_claims(claims)
    if registry is None:
        registry = default_registry
    result = serialize_compact(header, payload, key, registry)
    return result.decode('utf-8')


def decode(
        value: AnyStr,
        key: KeyFlexible,
        registry: Optional[JWTRegistry]=None) -> Token:
    """Decode the JSON Web Token string with the given key, and validate
    it with the claims requests. This method is a combination of the
    :function:`extract` and :function:`validate`.

    :param value: text of the JWT
    :param key: key used to verify the signature
    :param registry: a JWTRegistry to use
    :raise: BadSignatureError
    """
    obj = extract_compact(to_bytes(value))
    try:
        token = Token(obj.headers(), obj.claims)
    except ValueError:
        raise InvalidPayloadError('Payload should be a JSON dict')
    if registry is None:
        registry = default_registry

    typ = token.header.get('typ')
    if typ and typ != 'JWT':
        raise InvalidTypeError()

    registry.check_claims(token.claims)
    validate_compact(obj, key, registry)
    return token
