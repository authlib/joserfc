import random
from typing import Callable, Union, Any, AnyStr, Protocol
from .rfc7517 import (
    SymmetricKey,
    AsymmetricKey,
    CurveKey,
    Key,
    JWKRegistry,
    KeySet,
)
from .rfc7517 import types
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc8037.okp_key import OKPKey
from .rfc8812 import register_secp256k1
from .registry import Header


KeyCallable = Callable[[Any, bool], Key]
KeyFlexible = Union[AnyStr, Key, KeySet, KeyCallable]

__all__ = [
    "types",
    "JWKRegistry",
    "SymmetricKey",
    "AsymmetricKey",
    "CurveKey",
    "Key",
    "KeyCallable",
    "KeyFlexible",
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
    "KeySet",
    "guess_key",
]


def __register():
    JWKRegistry.register(OctKey)
    JWKRegistry.register(RSAKey)
    JWKRegistry.register(ECKey)
    JWKRegistry.register(OKPKey)
    # add {"crv": "secp256k1"} for ECKey
    register_secp256k1()


# register all key types
__register()


class GuestProtocol(Protocol):  # pragma: no cover
    def headers(self) -> Header:
        ...

    def set_kid(self, kid: str):
        ...


def guess_key(key: KeyFlexible, obj: GuestProtocol) -> Key:
    """Guess key from a various sources.

    :param key: a very flexible key
    :param obj: a protocol that has ``headers`` and ``set_kid`` methods
    """
    headers = obj.headers()

    if isinstance(key, (str, bytes)):
        rv_key = OctKey.import_key(key)

    elif isinstance(key, (SymmetricKey, AsymmetricKey)):
        rv_key = key

    elif isinstance(key, KeySet):
        kid = headers.get("kid")
        if not kid:
            # choose one key by random
            key: Key = random.choice(key.keys)
            # use side effect to add kid information
            obj.set_kid(key.kid)
            rv_key = key
        else:
            rv_key = key.get_by_kid(kid)

    elif callable(key):
        rv_key = key(obj)

    else:
        raise ValueError("Invalid key")

    return rv_key
