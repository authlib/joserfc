from ._types.headers import EHeader
from ._types.keys import Key


JWE_REGISTRY = {}


def serialize_compact(header: EHeader, payload, key: Key, sender_key=None):
    pass


def extract_compact(text: str):
    pass


def deserialize_compact(text: str, key: Key, sender_key=None):
    pass
