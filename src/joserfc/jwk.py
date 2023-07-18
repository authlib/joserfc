import typing as t
from .rfc7517 import (
    BaseKey,
    SymmetricKey,
    AsymmetricKey,
    CurveKey,
    JWKRegistry as _JWKRegistry,
    KeySet as _KeySet,
)
from .rfc7517 import types
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc8037.okp_key import OKPKey
from .rfc8812 import register_secp256k1
from .registry import Header


__all__ = [
    "types",
    "JWKRegistry",
    "BaseKey",
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

register_secp256k1()


class JWKRegistry(_JWKRegistry):
    """A registry for JWK to record ``joserfc`` supported key types.
    Normally, you would use explicit key types like ``OctKey``, ``RSAKey``;
    This registry provides a way to dynamically import and generate keys.
    For instance:

    .. code-block:: python

        from joserfc.jwk import JWKRegistry

        # instead of choosing which key type to use yourself,
        # JWKRegistry can import it automatically
        data = {"kty": "oct", "k": "..."}
        key = JWKRegistry.import_key(data)
    """
    key_types = {
        OctKey.key_type: OctKey,
        RSAKey.key_type: RSAKey,
        ECKey.key_type: ECKey,
        OKPKey.key_type: OKPKey,
    }


Key = t.Union[OctKey, RSAKey, ECKey, OKPKey]
KeyCallable = t.Callable[[t.Any], Key]


class KeySet(_KeySet):
    registry_cls = JWKRegistry


KeyFlexible = t.Union[t.AnyStr, Key, KeySet, KeyCallable]


class GuestProtocol(t.Protocol):  # pragma: no cover
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
        rv_key = OctKey.import_key(key)  # type: ignore

    elif isinstance(key, BaseKey):
        rv_key: Key = key  # type: ignore

    elif isinstance(key, KeySet):
        kid = headers.get("kid")
        if not kid:
            # choose one key by random
            rv_key: Key = key.pick_random_key(headers["alg"])  # type: ignore
            if rv_key is None:
                raise ValueError("Invalid key")
            # use side effect to add kid information
            obj.set_kid(rv_key.kid)
        else:
            rv_key: Key = key.get_by_kid(kid)  # type: ignore

    elif callable(key):
        rv_key = key(obj)  # type: ignore

    else:
        raise ValueError("Invalid key")

    return rv_key  # type: ignore
