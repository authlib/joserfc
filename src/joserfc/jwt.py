from typing import Optional, AnyStr
from .rfc7515 import CompactData, extract_compact
from .rfc7515.types import Header
from .rfc7519.claims import Claims, convert_claims
from .rfc7519.validators import JWTClaimsRequests
from .jws import serialize_compact, validate_compact
from .jwk import KeyFlexible
from .errors import InvalidTypeError
from .util import to_bytes, json_dumps


def encode(
    header: Header,
    claims: Claims,
    key: KeyFlexible,
    allowed_algorithms: Optional[list[str]]=None) -> str:

    # add ``typ`` in header
    header['typ'] = 'JWT'
    payload = convert_claims(claims)
    result = serialize_compact(header, payload, key, allowed_algorithms)
    return result.decode('utf-8')


def decode(
    value: AnyStr,
    key: KeyFlexible,
    validator: Optional[JWTClaimsRequests]=None,
    allowed_algorithms: Optional[list[str]]=None) -> CompactData:

    obj = extract_compact(to_bytes(value))
    validate(obj, key, validator, allowed_algorithms)
    return obj


def validate(
    obj: CompactData,
    key: KeyFlexible,
    validator: Optional[JWTClaimsRequests]=None,
    allowed_algorithms: Optional[list[str]]=None):

    typ = obj.header.get('typ')
    if typ and typ != 'JWT':
        raise InvalidTypeError()

    if validator is not None:
        validator.validate(obj.claims)
    validate_compact(obj, key, allowed_algorithms)
