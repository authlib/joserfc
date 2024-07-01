from __future__ import annotations
import typing as t
import warnings
from ._keys import (
    JWKRegistry,
    KeySet,
    OctKey,
    RSAKey,
    ECKey,
    OKPKey,
    Key,
)
from .rfc8812 import register_secp256k1
from .registry import Header


__all__ = [
    "JWKRegistry",
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

register_secp256k1()


class GuestProtocol(t.Protocol):  # pragma: no cover
    def headers(self) -> Header:
        ...

    def set_kid(self, kid: str) -> None:
        ...


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
