from __future__ import annotations
import typing as t
import random
from .rfc7517.types import AnyKey, KeyParameters, DictKey
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc8037.okp_key import OKPKey
from .util import to_bytes

__all__ = [
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
    "Key",
    "KeySet",
    "JWKRegistry",
]

Key = t.Union[OctKey, RSAKey, ECKey, OKPKey]


class JWKRegistry:
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
    key_types: t.Dict[str, t.Type[Key]] = {
        OctKey.key_type: OctKey,
        RSAKey.key_type: RSAKey,
        ECKey.key_type: ECKey,
        OKPKey.key_type: OKPKey,
    }

    @classmethod
    def import_key(
            cls,
            data: AnyKey,
            key_type: str | None = None,
            parameters: KeyParameters | None = None) -> Key:
        """A class method for importing a key from bytes, string, and dict.
        When ``value`` is a dict, this method can tell the key type automatically,
        otherwise, developers SHOULD pass the ``key_type`` themselves.

        :param data: the key data in bytes, string, or dict.
        :param key_type: an optional key type in string.
        :param parameters: extra key parameters
        :return: OctKey, RSAKey, ECKey, or OKPKey
        """
        if isinstance(data, dict) and key_type is None:
            if "kty" in data:
                key_type = data["kty"]  # type: ignore[assignment]
            else:
                raise ValueError("Missing key type")

        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        if isinstance(data, str):
            data = to_bytes(data)

        key_cls = cls.key_types[key_type]
        return key_cls.import_key(data, parameters)

    @classmethod
    def generate_key(
            cls,
            key_type: str,
            crv_or_size: str | int,
            parameters: KeyParameters | None = None,
            private: bool = True,
            auto_kid: bool = False) -> Key:
        """A class method for generating key according to the given key type.
        When ``key_type`` is "oct" and "RSA", the second parameter SHOULD be
        a key size in bits. When ``key_type`` is "EC" and "OKP", the second
        parameter SHOULD be a "crv" string.

        .. code-block:: python

            JWKRegistry.generate_key("RSA", 2048)
            JWKRegistry.generate_key("EC", "P-256")
        """
        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        key_cls = cls.key_types[key_type]
        return key_cls.generate_key(crv_or_size, parameters, private, auto_kid)  # type: ignore[arg-type]


KeySetSerialization = t.TypedDict("KeySetSerialization", {"keys": t.List[DictKey]})


class KeySet:
    #: keys in the key set
    keys: list[Key]

    registry_cls: t.Type[JWKRegistry] = JWKRegistry
    algorithm_keys: t.ClassVar[t.Dict[str, list[str]]] = {}

    def __init__(self, keys: list[Key]):
        for key in keys:
            key.ensure_kid()
        self.keys = keys

    def __iter__(self) -> t.Iterator[Key]:
        return iter(self.keys)

    def __bool__(self) -> bool:
        return bool(self.keys)

    def as_dict(self, private: bool | None = None, **params: t.Any) -> KeySetSerialization:
        keys: list[DictKey] = []

        for key in self.keys:
            # trigger key to generate kid via thumbprint
            key.ensure_kid()
            if isinstance(key, OctKey):
                keys.append(key.as_dict(**params))
            else:
                keys.append(key.as_dict(private=private, **params))
        return {"keys": keys}

    def get_by_kid(self, kid: str | None = None) -> Key:
        if kid is None and len(self.keys) == 1:
            return self.keys[0]

        for key in self.keys:
            if key.kid == kid:
                return key
        raise ValueError(f'No key for kid: "{kid}"')

    def pick_random_key(self, algorithm: str) -> t.Optional[Key]:
        key_types = self.algorithm_keys.get(algorithm)
        if key_types:
            keys = [k for k in self.keys if k.key_type in key_types]
        else:
            keys = self.keys
        if keys:
            return random.choice(keys)
        return None

    @classmethod
    def import_key_set(
            cls,
            value: KeySetSerialization,
            parameters: KeyParameters | None = None) -> "KeySet":
        keys: list[Key] = []

        for data in value["keys"]:
            keys.append(cls.registry_cls.import_key(data, parameters=parameters))

        return cls(keys)

    @classmethod
    def generate_key_set(
            cls,
            key_type: str,
            crv_or_size: str | int,
            parameters: KeyParameters | None = None,
            private: bool = True,
            count: int = 4) -> "KeySet":

        keys: list[Key] = []
        for _ in range(count):
            key = cls.registry_cls.generate_key(key_type, crv_or_size, parameters, private)
            keys.append(key)

        return cls(keys)
