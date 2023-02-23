import os
from typing import Optional
from abc import ABCMeta, abstractmethod
from .types import EncryptionData, Recipient
from .._registry import HeaderRegistryDict


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

    def check_iv(self, iv: bytes):
        if len(iv) * 8 != self.IV_SIZE:
            raise ValueError('Invalid "iv" size')

    @abstractmethod
    def encrypt(self, msg: bytes, obj: EncryptionData) -> EncryptionData:
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
    extra_headers: HeaderRegistryDict = {}

    @abstractmethod
    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key, sender_key=None):
        pass

    @abstractmethod
    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key, sender_key):
        pass
