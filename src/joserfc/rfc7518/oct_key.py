import random
import string
from typing import Optional
from ..util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from ..registry import KeyParameter
from ..rfc7517.models import SymmetricKey, NativeKeyBinding
from ..rfc7517.types import KeyParameters, DictKey


POSSIBLE_UNSAFE_KEYS = (
    b"-----BEGIN ",
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ecdsa-sha2-",
)


class OctBinding(NativeKeyBinding):
    @classmethod
    def convert_raw_key_to_dict(cls, value: bytes, private: bool) -> DictKey:
        k = urlsafe_b64encode(value).decode("utf-8")
        return {"k": k}

    @classmethod
    def import_from_dict(cls, value: DictKey):
        return urlsafe_b64decode(to_bytes(value["k"]))

    @classmethod
    def import_from_bytes(cls, value: bytes, password=None):
        # security check
        if value.startswith(POSSIBLE_UNSAFE_KEYS):
            raise ValueError("This key may not be safe to import")
        return value


class OctKey(SymmetricKey):
    """OctKey is a symmetric key, defined by RFC7518 Section 6.4.
    """
    key_type = "oct"
    binding = OctBinding

    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.4
    value_registry = {"k": KeyParameter("Key Value", "str", True, True)}

    @classmethod
    def generate_key(
            cls,
            key_size=256,
            parameters: Optional[KeyParameters] = None,
            private: bool = True) -> "OctKey":
        """Generate a ``OctKey`` with the given bit size (not bytes).

        :param key_size: size in bit
        :param parameters: extra parameter in JWK
        :param private: must be True
        """
        if not private:
            raise ValueError("oct key can not be generated as public")

        if key_size % 8 != 0:
            raise ValueError("Invalid bit size for oct key")

        length = key_size // 8
        rand = random.SystemRandom()
        chars = string.ascii_letters + string.digits
        value = "".join(rand.choice(chars) for _ in range(length))
        raw_key = to_bytes(value)
        return cls(raw_key, raw_key, parameters)
