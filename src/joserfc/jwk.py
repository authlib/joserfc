import typing as t
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


KeyCallable = t.Callable[[GuestProtocol], Key]
KeyFlexible = t.Union[str, bytes, Key, KeySet, KeyCallable]


def guess_key(key: KeyFlexible, obj: GuestProtocol, use_random: bool = False) -> Key:
    """Guess key from a various sources.

    :param key: a very flexible key
    :param obj: a protocol that has ``headers`` and ``set_kid`` methods
    :param use_random: pick a random key from key set
    """
    headers = obj.headers()

    rv_key: Key
    if isinstance(key, (str, bytes)):
        rv_key = OctKey.import_key(key)

    elif isinstance(key, (OctKey, RSAKey, ECKey, OKPKey)):
        rv_key = key

    elif isinstance(key, KeySet):
        kid = headers.get("kid")
        if not kid and use_random:
            # choose one key by random
            rv_key = key.pick_random_key(headers["alg"])  # type: ignore[assignment]
            if rv_key is None:
                raise ValueError("Invalid key")
            # use side effect to add kid information
            obj.set_kid(rv_key.kid)
        else:
            rv_key = key.get_by_kid(kid)

    elif callable(key):
        rv_key = key(obj)

    else:
        raise ValueError("Invalid key")

    return rv_key
