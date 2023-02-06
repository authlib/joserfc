from typing import Union
from .rfc7518.oct_key import OctKey


__all__ = [
    'OctKey',
    'JWK_REGISTRY',
    'generate_key',
]


JWK_REGISTRY = {
    OctKey.key_type: OctKey,
}


def generate_key(key_type: str, crv_or_size: Union[str, int], options=None, private=False):
    pass
