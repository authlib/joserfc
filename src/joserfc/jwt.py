from typing import Optional, List
from .rfc7515 import extract_compact
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
    allowed_algorithms: Optional[List[str]]=None) -> str:

    # add ``typ`` in header
    header['typ'] = 'JWT'
    payload = convert_claims(claims)
    result = serialize_compact(header, payload, key, allowed_algorithms)
    return result.decode('utf-8')


def decode(
    text: str,
    key: KeyFlexible,
    validator: Optional[JWTClaimsRequests]=None,
    allowed_algorithms: Optional[List[str]]=None) -> CompactData:

    obj = extract_compact(text)
    validate(obj, key, validator, allowed_algorithms)
    return obj


def validate(
    obj: CompactData,
    key: KeyFlexible,
    validator: JWTClaimsRequests
    allowed_algorithms: Optional[List[str]]=None):

    typ = header.get('typ')
    if typ and typ != 'JWT':
        raise InvalidTypeError()

    validator.validate(obj.claims)
    validate_compact(obj, key, allowed_algorithms)
