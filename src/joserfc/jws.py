from .rfc7517.keys import Key
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8812 import ES256K
from ._types.headers import SHeader
from ._util import json_b64encode, urlsafe_b64encode

# supported algs
JWS_REGISTRY = {alg.name: alg for alg in JWS_ALGORITHMS}
JWS_REGISTRY[ES256K.name] = ES256K

# predefined allowed algorithms
DEFAULT_ALLOWED_ALGORITHMS = [
]


def serialize_compact(
    header: SHeader,
    payload: bytes,
    key: Key,
    allowed_algorithms=None) -> bytes:

    assert key.is_private, "Private key is required to serialize the signature"

    if allowed_algorithms is None:
        allowed_algorithms = DEFAULT_ALLOWED_ALGORITHMS

    alg = header['alg']
    if alg not in allowed_algorithms:
        raise ValueError(f'Algorithm "{alg}" is not allowed in {allowed_algorithms}')

    algorithm = JWS_REGISTRY[alg]

    protected_segment = json_b64encode(header)
    payload_segment = urlsafe_b64encode(payload)

    # calculate signature
    signing_input = b'.'.join([protected_segment, payload_segment])
    signature = urlsafe_b64encode(algorithm.sign(signing_input, key))
    return b'.'.join([protected_segment, payload_segment, signature])


def extract_compact(text: str, allowed_algorithms=None):
    if allowed_algorithms is None:
        allowed_algorithms = DEFAULT_ALLOWED_ALGORITHMS


def deserialize_compact(text: str, key: Key, allowed_algorithms=None):
    pass


def extract(text: str):
    if text.count('.') == 2:
        return extract_compact(text)
