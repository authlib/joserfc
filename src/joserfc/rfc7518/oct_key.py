from ..util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
    generate_token,
)
from ..rfc7517 import SymmetricKey
from ..rfc7517.types import KeyOptions, KeyAny, KeyDict


POSSIBLE_UNSAFE_KEYS = (
    b'-----BEGIN ',
    b'ssh-rsa ',
    b'ssh-ed25519 ',
    b'ecdsa-sha2-',
)


class OctKey(SymmetricKey):
    key_type: str = 'oct'
    required_fields = frozenset(['kty', 'k'])

    def get_op_key(self, operation: str) -> bytes:
        self.check_key_op(operation)
        return self.raw_key

    def as_dict(self, **params) -> KeyDict:
        if self._tokens:
            data = self._tokens.copy()
        else:
            k = urlsafe_b64encode(self.raw_key).decode('utf-8')
            data = self.render_tokens({'k': k})
        data.update(params)
        return data

    @classmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None) -> 'OctKey':
        if isinstance(value, dict):
            cls.validate_tokens(value)
            bytes_value = urlsafe_b64decode(to_bytes(value['k']))
            return cls(bytes_value, options, value)
        if isinstance(value, str):
            value = to_bytes(value)

        # security check
        if value.startswith(POSSIBLE_UNSAFE_KEYS):
            raise ValueError('This key may not be safe to import')
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
