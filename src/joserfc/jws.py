from ._types.headers import SHeader
from ._types.keys import Key
from ._util.encode import json_b64encode, urlsafe_b64encode

JWS_REGISTRY = {}


def serialize_compact(header: SHeader, payload: bytes, key: Key) -> bytes:
    assert key.is_private, "Private key is required to serialize the signature"

    alg = header['alg']
    algorithm = JWS_REGISTRY[alg]

    protected_segment = json_b64encode(header)
    payload_segment = urlsafe_b64encode(payload)

    # calculate signature
    signing_input = b'.'.join([protected_segment, payload_segment])
    signature = urlsafe_b64encode(algorithm.sign(signing_input, key))
    return b'.'.join([protected_segment, payload_segment, signature])


def extract_compact(text: str):
    pass


def deserialize_compact(text: str, key: Key):
    pass


def extract(text: str):
    if text.count('.') == 2:
        return extract_compact(text)
