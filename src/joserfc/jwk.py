from .rfc7517 import (
    SymmetricKey,
    AsymmetricKey,
    Key,
    KeySet,
    JWK_REGISTRY,
    generate_key,
    import_key,
)
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc8037.okp_key import OKPKey
from .rfc7638 import thumbprint


__all__ = [
    'SymmetricKey',
    'AsymmetricKey',
    'Key',
    'KeySet',
    'OctKey',
    'RSAKey',
    'ECKey',
    'OKPKey',
    'JWK_REGISTRY',
    'generate_key',
    'import_key',
]

# register thumbprint method
KeySet.thumbprint = thumbprint

# register all key types
JWK_REGISTRY[OctKey.key_type] = OctKey
JWK_REGISTRY[RSAKey.key_type] = RSAKey
JWK_REGISTRY[ECKey.key_type] = ECKey
JWK_REGISTRY[OKPKey.key_type] = OKPKey
