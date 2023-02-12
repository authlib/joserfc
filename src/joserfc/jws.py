from .rfc7515 import compact
from .rfc7515 import ProtectedHeader, CompactData, extract_compact
from .rfc7517.keys import Key
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8812 import ES256K
from .errors import BadSignatureError

__all__ = [
    'serialize_compact',
    'extract_compact',
    'deserialize_compact',
]

# supported algs
JWS_REGISTRY = {alg.name: alg for alg in JWS_ALGORITHMS}
JWS_REGISTRY[ES256K.name] = ES256K

# predefined allowed algorithms
DEFAULT_ALLOWED_ALGORITHMS = [
    'HS256', 'RS256',
]


def serialize_compact(
    header: ProtectedHeader,
    payload: bytes,
    key: Key,
    allowed_algorithms=None) -> bytes:

    if allowed_algorithms is None:
        allowed_algorithms = DEFAULT_ALLOWED_ALGORITHMS

    alg = header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]
    return compact.serialize_compact(header, payload, algorithm, key)


def deserialize_compact(text: str, key: Key, allowed_algorithms=None) -> CompactData:
    if allowed_algorithms is None:
        allowed_algorithms = DEFAULT_ALLOWED_ALGORITHMS

    obj = extract_compact(text)
    alg = obj.header['alg']

    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    if obj.verify(algorithm, key):
        return obj
    raise BadSignatureError()
