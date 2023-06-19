import os
import typing as t
from abc import ABCMeta, abstractmethod
from ..registry import Header, HeaderRegistryDict


class Recipient:
    def __init__(self, parent: "EncryptionData", header: t.Optional[Header] = None):
        self.parent = parent
        self.header = header
        self.recipient_key = None
        self.encrypted_key: t.Optional[bytes] = None
        self.ephemeral_key = None
        self.segments = {}  # store temporary segments

    def headers(self) -> Header:
        rv = {}
        rv.update(self.parent.protected)
        if not self.parent.compact and self.parent.unprotected:
            rv.update(self.parent.unprotected)
        if self.header:
            rv.update(self.header)
        return rv

    def add_header(self, key: str, value):
        if self.parent.compact:
            self.parent.protected.update({key: value})
        else:
            self.header.update({key: value})

    def set_kid(self, kid: str):
        self.add_header("kid", kid)


class EncryptionData:
    def __init__(
            self,
            protected: Header,
            payload: t.Optional[bytes] = None,
            unprotected: t.Optional[Header] = None):
        self.protected = protected
        self.payload = payload
        self.unprotected = unprotected
        self.recipients: t.List[Recipient] = []
        self.cek: t.Optional[bytes] = None  # content encryption key
        self.plaintext = payload
        self.aad: t.Optional[bytes] = None  # aad for JSON serialization
        self.encoded = {}  # store the encoded segments
        self.decoded = {}  # store the decoded segments
        self.compact = False
        self.flatten = False

    def add_recipient(self, key, header: t.Optional[Header] = None):
        recipient = Recipient(self, header)
        recipient.recipient_key = key
        self.recipients.append(recipient)


class JWEEncModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = True
    algorithm_type = "JWE"
    algorithm_location = "enc"

    IV_SIZE: int
    cek_size: int

    def generate_cek(self) -> bytes:
        return os.urandom(self.cek_size // 8)

    def generate_iv(self) -> bytes:
        return os.urandom(self.IV_SIZE // 8)

    def check_iv(self, obj: EncryptionData) -> bytes:
        iv: bytes = obj.decoded["iv"]
        if len(iv) * 8 != self.IV_SIZE:
            raise ValueError('Invalid "iv" size')
        return iv

    @abstractmethod
    def encrypt(self, obj: EncryptionData) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, obj: EncryptionData) -> bytes:
        pass


class JWEZipModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = True
    algorithm_type = "JWE"
    algorithm_location = "zip"

    @abstractmethod
    def compress(self, s: bytes) -> bytes:
        pass

    @abstractmethod
    def decompress(self, s: bytes) -> bytes:
        pass


class JWEAlgModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = False
    key_size: t.Optional[int] = None
    algorithm_type = "JWE"
    algorithm_location = "alg"
    more_header_registry: HeaderRegistryDict = {}

    # key management mode
    key_encryption: bool = False
    key_agreement: bool = False

    @property
    def direct_mode(self) -> bool:
        return self.key_size is None

    @abstractmethod
    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key) -> bytes:
        pass

    @abstractmethod
    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key) -> bytes:
        pass
