from typing import Union, Dict, Type
from .models import Key
from .types import KeyAny, KeyOptions
from ..util import to_bytes

JWK_REGISTRY: Dict[str, Type[Key]] = {}


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
    private: bool=True):

    if key_type not in JWK_REGISTRY:
        raise ValueError(f'Invalid key type: "{key_type}"')

    key_cls = JWK_REGISTRY[key_type]
    return key_cls.generate_key(crv_or_size, options, private)
