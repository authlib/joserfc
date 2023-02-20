from typing import Optional, AnyStr, List
from .rfc7515.compact import CompactData, extract_compact
from .rfc7519.claims import Claims, convert_claims
from .rfc7519.validators import ClaimsOption, JWTClaimsRequests
from .jws import serialize_compact, validate_compact
from .jwk import KeyFlexible
from .errors import InvalidTypeError
from .util import to_bytes
from ._shared import Header


__all__ = [
    'Header',
    'Claims',
    'convert_claims',
    'ClaimsOption',
    'JWTClaimsRequests',
    'encode',
    'decode',
    'extract',
    'validate',
]


def encode(
        header: Header,
        claims: Claims,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None) -> str:
    """Encode a JSON Web Token with the given header, and claims.

    :param header: A dict of the JWT header
    :param claims: A dict of the JWT claims to be encoded
    :param key: key used to sign the signature
    :param allowed_algorithms: allowed "alg" models to use, default to HS256, RS256, ES256
    """

    # add ``typ`` in header
    header['typ'] = 'JWT'
    payload = convert_claims(claims)
    result = serialize_compact(header, payload, key, allowed_algorithms)
    return result.decode('utf-8')


def decode(
        value: AnyStr,
        key: KeyFlexible,
        validator: Optional[JWTClaimsRequests]=None,
        allowed_algorithms: Optional[List[str]]=None) -> CompactData:
    """Decode the JSON Web Token string with the given key, and validate
    it with the claims requests. This method is a combination of the
    :function:`extract` and :function:`validate`.

    :param value: text of the JWT
    :param key: key used to verify the signature
    :param validator: claims requests validator
    :param allowed_algorithms: allowed "alg" models to use,
        default to HS256, RS256, ES256
    :raise: BadSignatureError
    """
    obj = extract_compact(to_bytes(value))
    validate(obj, key, validator, allowed_algorithms)
    return obj


def extract(value: AnyStr) -> CompactData:
    return extract_compact(to_bytes(value))


def validate(
        obj: CompactData,
        key: KeyFlexible,
        validator: Optional[JWTClaimsRequests]=None,
        allowed_algorithms: Optional[List[str]]=None):

    typ = obj.header.get('typ')
    if typ and typ != 'JWT':
        raise InvalidTypeError()

    if validator is not None:
        validator.validate(obj.claims())
    validate_compact(obj, key, allowed_algorithms)
