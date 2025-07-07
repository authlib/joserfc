from __future__ import annotations
import typing as t
from ._keys import (
    JWKRegistry,
    KeySet,
    Key,
    KeySetSerialization,
)
from ._rfc7517.types import AnyKey, DictKey, KeyParameters
from ._rfc7518.oct_key import OctKey as OctKey
from ._rfc7518.rsa_key import RSAKey as RSAKey
from ._rfc7518.ec_key import ECKey as ECKey
from ._rfc8037.okp_key import OKPKey as OKPKey
from ._rfc8812 import register_secp256k1
from ._rfc7638 import calculate_thumbprint as thumbprint
from ._rfc9278 import calculate_thumbprint_uri as thumbprint_uri
from .registry import Header


__all__ = [
    # types
    "Key",
    "DictKey",
    "KeyParameters",
    "KeyCallable",
    "KeyFlexible",
    "KeySetSerialization",
    "KeyBase",
    "GuestProtocol",
    # modules
    "JWKRegistry",
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
    "KeySet",
    # methods
    "guess_key",
    "import_key",
    "generate_key",
    "thumbprint",
    "thumbprint_uri",
]

register_secp256k1()


class GuestProtocol(t.Protocol):  # pragma: no cover
    def headers(self) -> Header: ...

    def set_kid(self, kid: str) -> None: ...


KeyBase = t.Union[Key, KeySet]
KeyCallable = t.Callable[[GuestProtocol], KeyBase]
KeyFlexible = t.Union[KeyBase, KeyCallable]


def guess_key(key: KeyFlexible, obj: GuestProtocol, use_random: bool = False) -> Key:
    """Guess key from a various sources.

    :param key: a very flexible key
    :param obj: a protocol that has ``headers`` and ``set_kid`` methods
    :param use_random: pick a random key from key set
    """
    resolved_key: KeyBase
    if callable(key):
        resolved_key = key(obj)
    else:
        resolved_key = key

    if isinstance(resolved_key, (OctKey, RSAKey, ECKey, OKPKey)):
        return resolved_key
    elif isinstance(resolved_key, KeySet):
        headers = obj.headers()
        kid: str | None = headers.get("kid")
        if not kid and use_random:
            # choose one key by random
            return_key = resolved_key.pick_random_key(headers["alg"])
            if return_key is None:
                raise ValueError("Invalid key")
            return_key.ensure_kid()
            obj.set_kid(t.cast(str, return_key.kid))
        else:
            return_key = resolved_key.get_by_kid(kid)
        return return_key
    else:
        raise ValueError("Invalid key")


def import_key(data: AnyKey, key_type: str | None = None, parameters: KeyParameters | None = None) -> Key:
    """Importing a key from bytes, string, and dict. When ``value`` is a dict,
    this method can tell the key type automatically, otherwise, developers
    SHOULD pass the ``key_type`` themselves.

    :param data: the key data in bytes, string, or dict.
    :param key_type: an optional key type in string.
    :param parameters: extra key parameters
    :return: OctKey, RSAKey, ECKey, or OKPKey
    """
    return JWKRegistry.import_key(data, key_type, parameters)


def generate_key(
    key_type: str,
    crv_or_size: str | int | None = None,
    parameters: KeyParameters | None = None,
    private: bool = True,
    auto_kid: bool = False,
) -> Key:
    """Generating key according to the given key type. When ``key_type`` is
    "oct" and "RSA", the second parameter SHOULD be a key size in bits.
    When ``key_type`` is "EC" and "OKP", the second
    parameter SHOULD be a "crv" string.
    """
    return JWKRegistry.generate_key(key_type, crv_or_size, parameters, private, auto_kid)
