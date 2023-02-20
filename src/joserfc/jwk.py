import random
from typing import Callable, Union, Any
from ._shared import CompactProtocol
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


KeyCallable = Callable[[Any, bool], Key]
KeyFlexible = Union[Key, KeySet, KeyCallable]

__all__ = [
    'JWK_REGISTRY',
    'SymmetricKey',
    'AsymmetricKey',
    'Key',
    'KeyCallable',
    'KeyFlexible',
    'OctKey',
    'RSAKey',
    'ECKey',
    'OKPKey',
    'KeySet',
    'generate_key',
    'import_key',
    'guess_key',
]

# register thumbprint method
KeySet.thumbprint = staticmethod(thumbprint)

# register all key types
JWK_REGISTRY[OctKey.key_type] = OctKey
JWK_REGISTRY[RSAKey.key_type] = RSAKey
JWK_REGISTRY[ECKey.key_type] = ECKey
JWK_REGISTRY[OKPKey.key_type] = OKPKey


def guess_key(key: KeyFlexible, obj: CompactProtocol, operation: str='verify') -> Key:
    """Guess key from a various sources.

    :param key: a very flexible key
    :param obj: a JWS compact data
    :param operation: key operation
    """
    if isinstance(key, (SymmetricKey, AsymmetricKey)):
        return key

    elif isinstance(key, KeySet):
        headers = obj.headers()
        kid = headers.get('kid')

        if not kid and operation in OctKey.private_key_ops:
            # choose one key by random
            key: Key = random.choice(key.keys)
            # use side effect to add kid information
            obj.set_kid(key.kid)
            return key
        return key.get_by_kid(kid)

    elif callable(key):
        return key(obj, operation)

    raise ValueError("Invalid key")
