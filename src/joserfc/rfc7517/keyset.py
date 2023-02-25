from typing import List, Union, Optional, Callable
from .keys import Key, SymmetricKey
from .types import KeyOptions, KeySetDict
from .keygen import import_key, generate_key


class KeySet:
    thumbprint: Callable[[Key], str]

    def __init__(self, keys: List[Key]):
        self.keys = keys

    def as_dict(self, private=None, **params):
        keys = []

        for key in self.keys:
            if self.thumbprint and key.kid is None:
                key.kid = self.thumbprint(key)

            if isinstance(key, SymmetricKey):
                keys.append(key.as_dict(**params))
            else:
                keys.append(key.as_dict(private=private, **params))

        return {"keys": keys}

    def get_by_kid(self, kid: Optional[str]=None) -> Key:
        if kid is None and len(self.keys) == 1:
            return self.keys[0]

        for key in self.keys:
            if key.kid == kid:
                return key
        raise ValueError(f'No key for kid: "{kid}"')

    @classmethod
    def import_key_set(cls, value: KeySetDict, options: KeyOptions=None) -> 'KeySet':
        keys = []

        for data in value['keys']:
            key_type = data['kty']
            keys.append(import_key(key_type, data, options))

        return cls(keys)

    @classmethod
    def generate_key_set(
            cls,
            key_type: str,
            crv_or_size: Union[str, int],
            options: KeyOptions=None,
            private: bool=True,
            count: int=4) -> 'KeySet':

        keys = []
        for i in range(count):
            key = generate_key(key_type, crv_or_size, options, private)
            if cls.thumbprint:
                key.kid = cls.thumbprint(key)
            keys.append(key)

        return cls(keys)
