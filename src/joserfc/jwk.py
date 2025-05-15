from __future__ import annotations
import typing as t
import warnings
from ._keys import (
    JWKRegistry,
    KeySet,
    Key,
    KeySetSerialization,
)
from .rfc7517.types import AnyKey, KeyParameters
from .rfc7518.oct_key import OctKey as OctKey
from .rfc7518.rsa_key import RSAKey as RSAKey
from .rfc7518.ec_key import ECKey as ECKey
from .rfc8037.okp_key import OKPKey as OKPKey
from .rfc8812 import register_secp256k1
from .registry import Header


__all__ = [
    "JWKRegistry",
    "Key",
    "KeyCallable",
    "KeyFlexible",
    "KeySetSerialization",
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
    "KeySet",
    "KeyBase",
    "GuestProtocol",
    "guess_key",
    "import_key",
    "generate_key",
]

register_secp256k1()


class GuestProtocol(t.Protocol):  # pragma: no cover
    def headers(self) -> Header: ...

    def set_kid(self, kid: str) -> None: ...


KeyBase = t.Union[str, bytes, Key, KeySet]
KeyCallable = t.Callable[[GuestProtocol], KeyBase]
KeyFlexible = t.Union[KeyBase, KeyCallable]


def guess_key(key: KeyFlexible, obj: GuestProtocol, use_random: bool = False) -> Key:
    """Guess key from a various sources.

    :param key: a very flexible key
    :param obj: a protocol that has ``headers`` and ``set_kid`` methods
    :param use_random: pick a random key from key set
    """

    _norm_key: t.Union[Key, KeySet]
    if callable(key):
        _norm_key = _normalize_key(key(obj))
    else:
        _norm_key = _normalize_key(key)

    rv_key: Key
    if isinstance(_norm_key, KeySet):
        headers = obj.headers()
        kid = headers.get("kid")
        if not kid and use_random:
            # choose one key by random
            rv_key = _norm_key.pick_random_key(headers["alg"])  # type: ignore[assignment]
            if rv_key is None:
                raise ValueError("Invalid key")
            rv_key.ensure_kid()
            assert rv_key.kid is not None  # for mypy
            obj.set_kid(rv_key.kid)
        else:
            rv_key = _norm_key.get_by_kid(kid)
    elif isinstance(_norm_key, (OctKey, RSAKey, ECKey, OKPKey)):
        rv_key = _norm_key
    else:
        raise ValueError("Invalid key")
    return rv_key


def _normalize_key(key: KeyBase) -> Key | KeySet:
    if isinstance(key, (str, bytes)):  # pragma: no cover
        warnings.warn(
            "Please use a Key object instead of bytes or string.",
            DeprecationWarning,
            stacklevel=2,
        )
        return OctKey.import_key(key)
    return key


def import_key(
    data: AnyKey,
    key_type: str | None = None,
    parameters: KeyParameters | None = None
) -> Key:
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
