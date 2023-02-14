from typing import (
    Optional,
    Union,
    Dict,
    List,
    TypedDict,
)

DictKey = Dict[str, Union[str, List[str]]]

RawKey = Union[str, bytes, DictKey]

KeyOptions = Optional[TypedDict('KeyOptions', {
    'use': str,
    'key_ops': List[str],
    'alg': str,
    'kid': str,
    'x5u': str,
    'x5c': str,
    'x5t': str,
    'x5t#S256': str,
}, total=False)]
