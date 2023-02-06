from typing import Dict, FrozenSet
from .._util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from .._types.keys import PlainKey, KeyOptions, RawKey


class OctKey(PlainKey):
    key_type: str = 'oct'
    required_fields: FrozenSet[str] = frozenset(['kty', 'k'])

    def __init__(self, value: bytes, options: KeyOptions=None):
        super().__init__(value, options)

    def as_dict(self, **params) -> Dict[str, str]:
        k = urlsafe_b64encode(self.value).decode('utf-8')
        data = {'kty': self.kty, 'k': k}
        data.update(params)
        return data

    @classmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None) -> 'OctKey':
        if isinstance(value, dict):
            tokens = self.validate_tokens(value)
            bytes_value = urlsafe_b64decode(to_bytes(value['k']))
            key = cls(bytes_value, options)
            key._tokens = tokens
            return key
        if isinstance(value, str):
            value = to_bytes(value)
        return cls(value, options)
