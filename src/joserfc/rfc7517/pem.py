from abc import ABCMeta, abstractmethod
from typing import Optional

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key, load_ssh_public_key,
    Encoding, PrivateFormat, PublicFormat,
    BestAvailableEncryption, NoEncryption,
)
from cryptography.hazmat.backends import default_backend
from .types import KeyDict
from ..util import to_bytes


def load_pem_key(raw: bytes, ssh_type=None, key_type=None, password=None):
    if ssh_type and raw.startswith(ssh_type):
        return load_ssh_public_key(raw, backend=default_backend())

    if key_type == 'public':
        return load_pem_public_key(raw, backend=default_backend())

    if key_type == 'private' or password is not None:
        return load_pem_private_key(raw, password=password, backend=default_backend())

    if b'PUBLIC' in raw:
        return load_pem_public_key(raw, backend=default_backend())

    if b'PRIVATE' in raw:
        return load_pem_private_key(raw, password=password, backend=default_backend())

    if b'CERTIFICATE' in raw:
        cert = load_pem_x509_certificate(raw, default_backend())
        return cert.public_key()

    try:
        return load_pem_private_key(raw, password=password, backend=default_backend())
    except ValueError:
        return load_pem_public_key(raw, backend=default_backend())


def dump_pem_key(key, encoding=None, private=False, password=None) -> bytes:
    """Export key into PEM/DER format bytes.

    :param key: native cryptography key
    :param encoding: "PEM" or "DER"
    :param private: export private key or public key
    :param password: encrypt private key with password
    :return: bytes
    """

    if encoding is None or encoding == 'PEM':
        encoding = Encoding.PEM
    elif encoding == 'DER':
        encoding = Encoding.DER
    else:
        raise ValueError('Invalid encoding: {!r}'.format(encoding))

    if private:
        if password is None:
            encryption_algorithm = NoEncryption()
        else:
            encryption_algorithm = BestAvailableEncryption(to_bytes(password))
        return key.private_bytes(
            encoding=encoding,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
    return key.public_bytes(
        encoding=encoding,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


class CryptographyBinding(object, metaclass=ABCMeta):
    ssh_type: bytes

    @classmethod
    def import_key(cls, key_cls, value, options):
        if isinstance(value, dict):
            key_cls.validate_tokens(value)
            if 'd' in value:
                raw_key = cls.import_private_key(value)
            else:
                raw_key = cls.import_public_key(value)
            return key_cls(raw_key, options, value)

        if isinstance(value, str):
            value = to_bytes(value)

        raw_key = load_pem_key(value, cls.ssh_type)
        return key_cls(raw_key, options)

    @classmethod
    def as_dict(cls, key, private: Optional[bool]=None, **params) -> KeyDict:
        if key._tokens:
            data = key._tokens.copy()
            # clear private fields
            if private is False and key.is_private:
                for k in key.private_only_fields:
                    if k in data:
                        del data[k]

        elif private is True:
            data = cls.export_private_key(key.private_key)
        elif private is False:
            data = cls.export_public_key(key.public_key)
        elif key.is_private:
            data = cls.export_private_key(key.private_key)
        else:
            data = cls.export_public_key(key.public_key)

        data['kty'] = key.kty
        data.update(params)
        return data

    @staticmethod
    def as_bytes(key, encoding=None, private=None, password=None) -> bytes:
        if private is True:
            return dump_pem_key(key.private_key, encoding, private, password)
        elif private is False:
            return dump_pem_key(key.public_key, encoding, private, password)
        return dump_pem_key(key.raw_key, encoding, key.is_private, password)

    @staticmethod
    @abstractmethod
    def import_private_key(value):
        pass

    @staticmethod
    @abstractmethod
    def import_public_key(value):
        pass

    @staticmethod
    @abstractmethod
    def export_private_key(value):
        pass

    @staticmethod
    @abstractmethod
    def export_public_key(value):
        pass
