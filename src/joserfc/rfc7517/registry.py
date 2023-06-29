import typing as t
from .models import Key, SymmetricKey
from .types import KeyAny, KeyOptions, KeySetDict
from ..util import to_bytes


class JWKRegistry:
    key_types: t.Dict[str, t.Type[Key]] = {}

    @classmethod
    def register(cls, model: t.Type[Key]):
        cls.key_types[model.key_type] = model

    @classmethod
    def import_key(cls, value: KeyAny,  key_type: t.Optional[str] = None, options: KeyOptions = None) -> Key:
        if isinstance(value, dict) and key_type is None:
            if "kty" not in value:
                raise ValueError("Missing key type")
            key_type = value["kty"]

        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        if isinstance(value, str):
            value = to_bytes(value)

        key_cls = cls.key_types[key_type]
        return key_cls.import_key(value, options)  # type: ignore

    @classmethod
    def generate_key(
            cls,
            key_type: str,
            crv_or_size: t.Union[str, int],
            options: KeyOptions = None,
            private: bool = True) -> Key:
        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        key_cls = cls.key_types[key_type]
        return key_cls.generate_key(crv_or_size, options, private)  # type: ignore


class KeySet:
    def __init__(self, keys: t.List[Key]):
        self.keys = keys

    def as_dict(self, private=None, **params):
        keys = []

        for key in self.keys:
            # trigger key to generate kid via thumbprint
            assert key.kid is not None
            if isinstance(key, SymmetricKey):
                keys.append(key.as_dict(**params))
            else:
                keys.append(key.as_dict(private=private, **params))
        return {"keys": keys}

    def get_by_kid(self, kid: t.Optional[str] = None) -> Key:
        if kid is None and len(self.keys) == 1:
            return self.keys[0]

        for key in self.keys:
            if key.kid == kid:
                return key
        raise ValueError(f'No key for kid: "{kid}"')

    @classmethod
    def import_key_set(cls, value: KeySetDict, options: KeyOptions = None) -> "KeySet":
        keys = []

        for data in value["keys"]:
            keys.append(JWKRegistry.import_key(data, options=options))

        return cls(keys)

    @classmethod
    def generate_key_set(
            cls,
            key_type: str,
            crv_or_size: t.Union[str, int],
            options: KeyOptions = None,
            private: bool = True,
            count: int = 4) -> "KeySet":

        keys = []
        for i in range(count):
            key = JWKRegistry.generate_key(key_type, crv_or_size, options, private)
            keys.append(key)

        return cls(keys)
