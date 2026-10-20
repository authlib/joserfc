import secrets
import typing as t
import warnings
from typing import Self

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
    load_ssh_public_key,
)

from .._rfc7517.models import NativeKeyBinding, SymmetricKey
from .._rfc7517.types import AnyKey, DictKey, KeyParameters
from ..errors import SecurityWarning
from ..registry import KeyParameter
from ..util import (
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)

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
    def convert_raw_key_to_dict(cls, raw_key: bytes, private: bool) -> DictKey:
        k = urlsafe_b64encode(raw_key).decode("utf-8")
        return {"k": k}

    @classmethod
    def import_from_dict(cls, value: DictKey) -> bytes:
        return cls.import_from_bytes(urlsafe_b64decode(to_bytes(value["k"])))

    @classmethod
    def import_from_bytes(cls, value: bytes, password: str | bytes | None = None) -> bytes:
        # Reject recognized public keys, while retaining warnings for input
        # that only resembles an asymmetric key (see issue #32).
        if value.startswith(b"0"):
            loader = load_der_public_key
        elif value.startswith(b"-----BEGIN "):
            loader = load_pem_public_key
        elif value.startswith((b"ssh-", b"ecdsa-sha2-")):
            loader = load_ssh_public_key
        else:
            loader = None

        if loader is not None:
            try:
                loader(value)
            except (ValueError, UnsupportedAlgorithm):
                pass
            else:
                raise ValueError("Asymmetric public keys must not be used as oct keys")

        if value.startswith(POSSIBLE_UNSAFE_KEYS):
            warnings.warn("This key should not be used as an oct key", SecurityWarning, stacklevel=2)
        return value


class OctKey(SymmetricKey):
    """OctKey is a symmetric key, defined by RFC7518 Section 6.4."""

    key_type = "oct"
    binding = OctBinding

    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.4
    value_registry = {"k": KeyParameter("Key Value", "str", True, True)}

    @classmethod
    def import_key(
        cls,
        value: AnyKey,
        parameters: KeyParameters | None = None,
        password: str | bytes | None = None,
    ) -> Self:
        key = super().import_key(value, parameters, password)
        if not key.raw_value:
            # An empty oct key material produces a deterministic HMAC digest
            # that any party can reproduce, allowing trivial signature forgery
            # in JWS HS256/HS384/HS512 verification. Reject outright rather
            # than emitting a SecurityWarning that callers commonly suppress.
            raise ValueError("oct key material must not be empty")
        if len(key.raw_value) < 14:
            # https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
            warnings.warn("Key size should be >= 112 bits", SecurityWarning, stacklevel=2)
        return key

    @classmethod
    def generate_key(
        cls,
        key_size: int | None = 256,
        parameters: KeyParameters | None = None,
        private: bool = True,
        auto_kid: bool = False,
    ) -> Self:
        """Generate a ``OctKey`` with the given bit size (not bytes).

        :param key_size: size in bit
        :param parameters: extra parameter in JWK
        :param private: must be True
        :param auto_kid: add ``kid`` automatically
        """
        if not private:
            raise ValueError("oct key can not be generated as public")

        if key_size is None:
            key_size = 256

        if key_size % 8 != 0:
            raise ValueError("Invalid bit size for oct key")

        if key_size < 112:
            # https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final
            warnings.warn("Key size should be >= 112 bits", SecurityWarning, stacklevel=2)

        raw_key = secrets.token_bytes(key_size // 8)
        key = cls(raw_key, raw_key, parameters)
        if auto_kid:
            key.ensure_kid()
        return key

    def as_dict(self, private: bool = False, **params: t.Any) -> DictKey:
        return super().as_dict(private=True, **params)
