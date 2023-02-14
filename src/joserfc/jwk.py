from typing import Union, Dict, Any, Optional
from .rfc7517 import (
    SymmetricKey,
    AsymmetricKey,
    Key,
    KeySet,
)
from .rfc7517.types import KeyOptions
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc7638 import thumbprint


__all__ = [
    'SymmetricKey',
    'AsymmetricKey',
    'Key',
    'KeySet',
    'OctKey',
    'RSAKey',
    'ECKey',
    'JWK_REGISTRY',
    'generate_key',
]


JWK_REGISTRY = {
    OctKey.key_type: OctKey,
    RSAKey.key_type: RSAKey,
    ECKey.key_type: ECKey,
}

KeySet.registry = JWK_REGISTRY
# register thumbprint method
KeySet.thumbprint = thumbprint


def generate_key(
    key_type: str,
    crv_or_size: Union[str, int],
    options: KeyOptions=None,
    private: bool=False):

    if key_type not in JWK_REGISTRY:
        raise ValueError(f'Invalid key type: "{key_type}"')

    key_class = JWK_REGISTRY[key_type]
    return key_class.generate_key(crv_or_size, options, private)
