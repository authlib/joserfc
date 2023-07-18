import typing as t
import random
from .models import BaseKey as Key, SymmetricKey
from .types import KeyDict, KeySetDict, KeyParameters
from .registry import JWKRegistry


class KeySet:
    #: keys in the key set
    keys: t.List[Key]

    registry_cls: t.ClassVar[t.Type[JWKRegistry]]
    algorithm_keys: t.ClassVar[t.Dict[str, t.List[str]]] = {}

    def __init__(self, keys: t.List[Key]):
        self.keys = keys

    def __iter__(self) -> t.Iterator[Key]:
        return iter(self.keys)

    def as_dict(self, private: t.Optional[bool] = None, **params: t.Any) -> KeySetDict:
        keys: t.List[KeyDict] = []

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
            value: KeySetDict,
            parameters: t.Optional[KeyParameters] = None) -> "KeySet":
        keys = []

        for data in value["keys"]:
            keys.append(cls.registry_cls.import_key(data, parameters=parameters))

        return cls(keys)

    @classmethod
    def generate_key_set(
            cls,
            key_type: str,
            crv_or_size: t.Union[str, int],
            parameters: t.Optional[KeyParameters] = None,
            private: bool = True,
            count: int = 4) -> "KeySet":

        keys = []
        for _ in range(count):
            key = cls.registry_cls.generate_key(key_type, crv_or_size, parameters, private)
            keys.append(key)

        return cls(keys)
