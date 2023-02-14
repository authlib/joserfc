from .rfc7515 import (
    CompactData,
    extract_compact,
)
from .rfc7517.keys import Key
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8812 import ES256K
from .errors import BadSignatureError
from ._types import Header, check_header

__all__ = [
    'CompactData',
    'serialize_compact',
    'extract_compact',
    'deserialize_compact',
    'validate_compact',
]

# supported algs
JWS_REGISTRY = {alg.name: alg for alg in JWS_ALGORITHMS}
JWS_REGISTRY[ES256K.name] = ES256K

#: Recommended "alg" (Algorithm) Header Parameter Values for JWS
#: by `RFC7618 Section 3.1`_
#: .. `RFC7618 Section 3.1`_: https://www.rfc-editor.org/rfc/rfc7518#section-3.1
RECOMMENDED_ALGORITHMS = [
    'HS256',  # Required
    'RS256',  # Recommended
    'ES256',  # Recommended+
]


def serialize_compact(
    header: Header,
    payload: bytes,
    key: Key,
    allowed_algorithms=None) -> bytes:

    check_header(header, ['alg'])

    if allowed_algorithms is None:
        allowed_algorithms = RECOMMENDED_ALGORITHMS

    alg = header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]

    obj = CompactData(header, payload)
    return obj.sign(algorithm, key)


def validate_compact(obj: CompactData, key: Key, allowed_algorithms=None) -> bool:
    if allowed_algorithms is None:
        allowed_algorithms = RECOMMENDED_ALGORITHMS

    alg = obj.header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]
    return obj.verify(algorithm, key)


def deserialize_compact(text: str, key: Key, allowed_algorithms=None) -> CompactData:
    obj = extract_compact(text)
    if validate_compact(obj, key, allowed_algorithms):
        return obj
    raise BadSignatureError()
