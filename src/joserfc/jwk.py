from typing import Union
from .rfc7517.keys import SymmetricKey, AsymmetricKey
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey


__all__ = [
    'SymmetricKey',
    'AsymmetricKey',
    'OctKey',
    'RSAKey',
    'JWK_REGISTRY',
    'generate_key',
]


JWK_REGISTRY = {
    OctKey.key_type: OctKey,
    RSAKey.key_type: RSAKey,
}


def generate_key(key_type: str, crv_or_size: Union[str, int], options=None, private=False):
    pass
