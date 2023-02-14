from typing import Optional, List, Union, Callable
from .rfc7515 import (
    CompactData,
    extract_compact,
)
from .rfc7515.types import Header, check_header
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8812 import ES256K
from .errors import BadSignatureError
from .jwk import Key, KeyFlexible, guess_key

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
    key: KeyFlexible,
    allowed_algorithms: Optional[List[str]]=None) -> bytes:

    check_header(header, ['alg'])

    if allowed_algorithms is None:
        allowed_algorithms = RECOMMENDED_ALGORITHMS

    alg = header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]

    obj = CompactData(header, payload)
    key: Key = guess_key(key, obj, 'sign')
    return obj.sign(algorithm, key)


def validate_compact(
    obj: CompactData,
    key: KeyFlexible,
    allowed_algorithms: Optional[List[str]]=None) -> bool:

    if allowed_algorithms is None:
        allowed_algorithms = RECOMMENDED_ALGORITHMS

    alg = obj.header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]
    key: Key = guess_key(key, obj, 'verify')
    return obj.verify(algorithm, key)


def deserialize_compact(
    text: str,
    key: KeyFlexible,
    allowed_algorithms: Optional[List[str]]=None) -> CompactData:

    obj = extract_compact(text)

    if validate_compact(obj, key, allowed_algorithms):
        return obj

    raise BadSignatureError()
