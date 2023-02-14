from typing import Optional, List
from .rfc7517.keys import Key
from .rfc7519.claims import Claims, convert_claims
from .jws import serialize_compact, deserialize_compact
from ._types import Header
from ._util import to_bytes, json_dumps


def encode(
    header: Header,
    claims: Claims,
    key: Key,
    allowed_algorithms: Optional[List[str]]=None) -> str:

    # add ``typ`` in header
    header['typ'] = 'JWT'
    payload = convert_claims(claims)
    result = serialize_compact(header, payload, key, allowed_algorithms)
    return result.decode('utf-8')


def decode(text: str, key: Key):
    pass
