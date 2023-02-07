from typing import FrozenSet
from .._util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from ..rfc7517.keys import SymmetricKey, KeyOptions, RawKey, DictKey


class OctKey(SymmetricKey):
    key_type: str = 'oct'
    required_fields: FrozenSet[str] = frozenset(['kty', 'k'])

    def __init__(self, value: bytes, options: KeyOptions=None):
        super().__init__(value, options)

    def as_dict(self, **params) -> DictKey:
        if self._tokens:
            data = self._tokens.copy()
        else:
            k = urlsafe_b64encode(self.value).decode('utf-8')
            data = self.render_tokens({'k': k})
        data.update(params)
        return data

    def get_op_key(self, operation: str):
        return self.value

    @classmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None) -> 'OctKey':
        if isinstance(value, dict):
            tokens = cls.validate_tokens(value)
            bytes_value = urlsafe_b64decode(to_bytes(value['k']))
            key = cls(bytes_value, options)
            key._tokens = key.render_tokens(tokens)
            return key
        if isinstance(value, str):
            value = to_bytes(value)
        return cls(value, options)
