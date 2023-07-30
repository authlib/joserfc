import typing as t
from abc import ABCMeta, abstractmethod
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    load_ssh_public_key,
    load_ssh_private_key,
    load_der_private_key,
    load_der_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    KeySerializationEncryption,
    BestAvailableEncryption,
    NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from .models import NativeKeyBinding, GenericKey
from .types import DictKey
from ..util import to_bytes


def load_pem_key(
        raw: bytes,
        ssh_type: t.Optional[bytes] = None,
        password: t.Optional[bytes] = None) -> t.Any:
    key: t.Any
    if ssh_type and raw.startswith(ssh_type):
        key = load_ssh_public_key(raw, backend=default_backend())

    elif b"OPENSSH PRIVATE" in raw:
        key = load_ssh_private_key(raw, password=password, backend=default_backend())

    elif b"PUBLIC" in raw:
        key = load_pem_public_key(raw, backend=default_backend())

    elif b"PRIVATE" in raw:
        key = load_pem_private_key(raw, password=password, backend=default_backend())

    else:
        try:
            key = load_der_private_key(raw, password=password, backend=default_backend())
        except ValueError:
            key = load_der_public_key(raw, backend=default_backend())
    return key


def dump_pem_key(
        key: t.Any,
        encoding: t.Optional[t.Literal["PEM", "DER"]] = None,
        private: t.Optional[bool] = False,
        password: t.Optional[t.Any] = None) -> bytes:
    """Export key into PEM/DER format bytes.

    :param key: native cryptography key
    :param encoding: "PEM" or "DER"
    :param private: export private key or public key
    :param password: encrypt private key with password
    :return: bytes
    """

    if encoding is None or encoding == "PEM":
        encoding_enum = Encoding.PEM
    elif encoding == "DER":
        encoding_enum = Encoding.DER
    else:  # pragma: no cover
        raise ValueError("Invalid encoding: {!r}".format(encoding))

    if private:
        encryption_algorithm: KeySerializationEncryption
        if password is None:
            encryption_algorithm = NoEncryption()
        else:
            encryption_algorithm = BestAvailableEncryption(to_bytes(password))
        return key.private_bytes(
            encoding=encoding_enum,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    return key.public_bytes(
        encoding=encoding_enum,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


class CryptographyBinding(NativeKeyBinding, metaclass=ABCMeta):
    ssh_type: bytes

    @classmethod
    def convert_raw_key_to_dict(cls, raw_key: t.Any, private: bool) -> DictKey:
        if private:
            return cls.export_private_key(raw_key)
        return cls.export_public_key(raw_key)

    @classmethod
    def import_from_dict(cls, value: DictKey) -> t.Any:
        if "d" in value:
            return cls.import_private_key(value)
        return cls.import_public_key(value)

    @classmethod
    def import_from_bytes(
            cls,
            value: bytes,
            password: t.Optional[t.Any] = None) -> t.Any:
        if password is not None:
            password = to_bytes(password)
        return load_pem_key(value, cls.ssh_type, password)

    @staticmethod
    def as_bytes(
            key: GenericKey,
            encoding: t.Optional[t.Literal["PEM", "DER"]] = None,
            private: t.Optional[bool] = False,
            password: t.Optional[t.Any] = None) -> bytes:
        if private is True:
            return dump_pem_key(key.private_key, encoding, private, password)
        elif private is False:
            return dump_pem_key(key.public_key, encoding, private, password)
        return dump_pem_key(key.raw_value, encoding, key.is_private, password)

    @staticmethod
    @abstractmethod
    def import_private_key(value) -> t.Any:
        pass

    @staticmethod
    @abstractmethod
    def import_public_key(value) -> t.Any:
        pass

    @staticmethod
    @abstractmethod
    def export_private_key(value) -> t.Any:
        pass

    @staticmethod
    @abstractmethod
    def export_public_key(value) -> t.Any:
        pass
