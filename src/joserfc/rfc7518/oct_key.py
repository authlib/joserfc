from __future__ import annotations
from typing import Any
from os import urandom
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
    b"---- BEGIN ",
    b"ssh-rsa ",
    b"ssh-dss ",
    b"ssh-ed25519 ",
    b"ecdsa-sha2-",
)


class OctBinding(NativeKeyBinding):
    @classmethod
    def convert_raw_key_to_dict(cls, value: bytes, private: bool) -> DictKey:
        k = urlsafe_b64encode(value).decode("utf-8")
        return {"k": k}

    @classmethod
    def import_from_dict(cls, value: DictKey) -> bytes:
        return urlsafe_b64decode(to_bytes(value["k"]))

    @classmethod
    def import_from_bytes(cls, value: bytes, password: Any | None = None) -> bytes:
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
            key_size: int = 256,
            parameters: KeyParameters | None = None,
            private: bool = True,
            auto_kid: bool = False) -> "OctKey":
        """Generate a ``OctKey`` with the given bit size (not bytes).

        :param key_size: size in bit
        :param parameters: extra parameter in JWK
        :param private: must be True
        :param auto_kid: add ``kid`` automatically
        """
        if not private:
            raise ValueError("oct key can not be generated as public")

        if key_size % 8 != 0:
            raise ValueError("Invalid bit size for oct key")

        value = urandom(key_size // 8)
        raw_key = to_bytes(value)
        key: OctKey = cls(raw_key, raw_key, parameters)
        if auto_kid:
            key.ensure_kid()
        return key
