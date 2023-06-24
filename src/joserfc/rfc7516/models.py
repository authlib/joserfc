import os
import typing as t
from abc import ABCMeta, abstractmethod
from ..rfc7517.models import Key
from ..registry import Header, HeaderRegistryDict


class Recipient:
    def __init__(
            self,
            parent: t.Union["CompactEncryption", "JSONEncryption"],
            header: t.Optional[Header] = None,
            key: t.Optional[Key]=None):
        self.__parent = parent
        self.header = header
        self.recipient_key = key
        self.encrypted_key: t.Optional[bytes] = None
        self.ephemeral_key = None
        self.segments = {}  # store temporary segments

    def headers(self) -> Header:
        rv = {}
        rv.update(self.__parent.protected)
        if isinstance(self.__parent, JSONEncryption) and self.__parent.unprotected:
            rv.update(self.__parent.unprotected)
        if self.header:
            rv.update(self.header)
        return rv

    def add_header(self, k: str, v: t.Any):
        if isinstance(self.__parent, CompactEncryption):
            self.__parent.protected.update({k: v})
        else:
            self.header.update({k: v})

    def set_kid(self, kid: str):
        self.add_header("kid", kid)


class CompactEncryption:
    def __init__(self, protected: Header, plaintext: t.Optional[bytes] = None):
        self.protected = protected
        self.plaintext = plaintext
        self.recipient: t.Optional[Recipient] = None
        self.bytes_segments: t.Dict[str, bytes] = {}  # store the decoded segments
        self.base64_segments: t.Dict[str, bytes] = {}  # store the encoded segments

    def add_recipient(self, key: Key, header: t.Optional[Header] = None):
        recipient = Recipient(self, header, key)
        self.recipient = recipient

    @property
    def recipients(self) -> t.List[Recipient]:
        return [self.recipient]


class JSONEncryption:
    def __init__(
            self,
            protected: Header,
            plaintext: t.Optional[bytes] = None,
            unprotected: t.Optional[Header] = None,
            aad: t.Optional[bytes] = None,
            flatten: bool=False):
        self.protected = protected
        self.plaintext = plaintext
        self.unprotected = unprotected
        self.aad: t.Optional[bytes] = aad
        self.flatten = flatten
        self.recipients: t.List[Recipient] = []
        self.bytes_segments: t.Dict[str, bytes] = {}  # store the decoded segments
        self.base64_segments: t.Dict[str, bytes] = {}  # store the encoded segments

    def add_recipient(self, key: Key, header: t.Optional[Header] = None):
        recipient = Recipient(self, header, key)
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

    def check_iv(self, iv: bytes) -> bytes:
        if len(iv) * 8 != self.IV_SIZE:
            raise ValueError('Invalid "iv" size')
        return iv

    @abstractmethod
    def encrypt(self, plaintext: bytes, cek: bytes, iv: bytes, aad: bytes) -> (bytes, bytes):
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, tag: bytes, cek: bytes, iv: bytes, aad: bytes) -> bytes:
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


class KeyManagement:
    name: str
    description: str
    recommended: bool = False
    key_size: t.Optional[int] = None
    algorithm_type = "JWE"
    algorithm_location = "alg"
    more_header_registry: HeaderRegistryDict = {}
    key_agreement: bool = False

    @property
    def direct_mode(self) -> bool:
        return self.key_size is None


class JWEDirectEncryption(KeyManagement, metaclass=ABCMeta):
    @abstractmethod
    def derive_cek(self, size: int, recipient: Recipient) -> bytes:
        pass


class JWEKeyEncryption(KeyManagement, metaclass=ABCMeta):
    @abstractmethod
    def encrypt_cek(self, cek: bytes, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def decrypt_cek(self, recipient: Recipient) -> bytes:
        pass


class JWEKeyWrapping(KeyManagement, metaclass=ABCMeta):
    @abstractmethod
    def wrap_cek(self, cek: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def unwrap_cek(self, ek: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt_cek(self, cek: bytes, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def decrypt_cek(self, recipient: Recipient) -> bytes:
        pass


class JWEKeyAgreement(KeyManagement, metaclass=ABCMeta):
    key_agreement = True

    @abstractmethod
    def encrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def decrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def wrap_cek_with_auk(self, cek: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def unwrap_cek_with_auk(self, ek: bytes, key: bytes) -> bytes:
        pass


JWEAlgModel = t.Union[JWEKeyEncryption, JWEKeyWrapping, JWEKeyAgreement, JWEDirectEncryption]
