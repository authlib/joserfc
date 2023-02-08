from typing import FrozenSet
from .._util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
    generate_token,
)
from ..rfc7517.keys import SymmetricKey, KeyOptions, RawKey, DictKey


class OctKey(SymmetricKey):
    key_type: str = 'oct'
    required_fields: FrozenSet[str] = frozenset(['kty', 'k'])

    def __init__(self, value: bytes, options: KeyOptions=None):
        super().__init__(value, options)

    def get_op_key(self, operation: str) -> bytes:
        self.check_key_op(operation)
        return self.raw_key

    def as_dict(self, **params) -> DictKey:
        if self._tokens:
            data = self._tokens.copy()
        else:
            k = urlsafe_b64encode(self.value).decode('utf-8')
            data = self.render_tokens({'k': k})
        data.update(params)
        return data

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

    @classmethod
    def generate_key(cls, key_size=256, options=None, private=True):
        """Generate a ``OctKey`` with the given bit size."""
        if not private:
            raise ValueError('oct key can not be generated as public')

        if key_size % 8 != 0:
            raise ValueError('Invalid bit size for oct key')

        value = generate_token(key_size // 8)
        return cls(to_bytes(value), options)
