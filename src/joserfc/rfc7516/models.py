import os
from typing import Optional
from abc import ABCMeta, abstractmethod
from .types import EncryptionData, Recipient
from ..registry import HeaderRegistryDict


class JWEEncModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = True
    algorithm_type = 'JWE'
    algorithm_location = 'enc'

    IV_SIZE: int
    cek_size: int

    def generate_cek(self) -> bytes:
        return os.urandom(self.cek_size // 8)

    def generate_iv(self) -> bytes:
        return os.urandom(self.IV_SIZE // 8)

    def check_iv(self, obj: EncryptionData) -> bytes:
        iv: bytes = obj.decoded['iv']
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
    algorithm_type = 'JWE'
    algorithm_location = 'zip'

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
    key_size: Optional[int] = None
    algorithm_type = 'JWE'
    algorithm_location = 'alg'
    more_header_registry: HeaderRegistryDict = {}

    # key management mode
    key_encryption: bool = False
    key_wrapping: bool = False
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
