from typing import Dict, List, Union, Optional, Callable
from .keys import Key
from .types import KeyAny, KeyOptions, KeySetDict
from ..util import to_bytes

#: registry to store all registered keys
JWK_REGISTRY: Dict[str, Key] = {}


def import_key(
    key_type: str,
    value: KeyAny,
    options: KeyOptions=None) -> Key:

    if key_type not in JWK_REGISTRY:
        raise ValueError(f'Invalid key type: "{key_type}"')

    if isinstance(value, str):
        value = to_bytes(value)

    key_cls = JWK_REGISTRY[key_type]
    return key_cls.import_key(value, options)


def generate_key(
    key_type: str,
    crv_or_size: Union[str, int],
    options: KeyOptions=None,
    private: bool=False):

    if key_type not in JWK_REGISTRY:
        raise ValueError(f'Invalid key type: "{key_type}"')

    key_cls = JWK_REGISTRY[key_type]
    return key_cls.generate_key(crv_or_size, options, private)


class KeySet:
    thumbprint: Optional[Callable[[Key], str]] = None

    def __init__(self, keys: List[Key]):
        self.keys = keys

    def as_dict(self):
        keys = []

        for key in self.keys:
            if self.thumbprint is not None and key.kid is None:
                key.kid = self.thumbprint(key)

            keys.append(key.tokens)

        return {"keys": keys}

    @classmethod
    def import_key(cls, value: KeySetDict, options: KeyOptions=None) -> 'KeySet':
        keys = []

        for data in value['keys']:
            key_type = data['kty']
            keys.append(import_key(key_type, value, options))

        return cls(keys)
