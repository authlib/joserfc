import random
import string
from ..util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from ..registry import KeyParameter, is_str
from ..rfc7517.models import SymmetricKey, NativeKeyBinding
from ..rfc7517.types import KeyOptions, KeyDict


POSSIBLE_UNSAFE_KEYS = (
    b'-----BEGIN ',
    b'ssh-rsa ',
    b'ssh-ed25519 ',
    b'ecdsa-sha2-',
)


class OctBinding(NativeKeyBinding):
    @classmethod
    def convert_raw_key_to_dict(cls, value: bytes, private: bool) -> KeyDict:
        k = urlsafe_b64encode(value).decode('utf-8')
        return {'k': k}

    @classmethod
    def import_from_dict(cls, value: KeyDict):
        return urlsafe_b64decode(to_bytes(value['k']))

    @classmethod
    def import_from_bytes(cls, value: bytes):
        # security check
        if value.startswith(POSSIBLE_UNSAFE_KEYS):
            raise ValueError('This key may not be safe to import')
        return value


class OctKey(SymmetricKey):
    key_type: str = 'oct'
    binding = OctBinding
    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.4
    value_registry = {
        'k': KeyParameter('Key Value', True, True, is_str)
    }

    @classmethod
    def generate_key(cls, key_size=256, options: KeyOptions=None, private: bool=True):
        """Generate a ``OctKey`` with the given bit size."""
        if not private:
            raise ValueError('oct key can not be generated as public')

        if key_size % 8 != 0:
            raise ValueError('Invalid bit size for oct key')

        length = key_size // 8
        rand = random.SystemRandom()
        chars = string.ascii_letters + string.digits
        value = ''.join(rand.choice(chars) for _ in range(length))
        raw_key = to_bytes(value)
        return cls(raw_key, raw_key, options)
