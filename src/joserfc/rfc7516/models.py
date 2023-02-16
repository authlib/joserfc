import os
from typing import Optional
from abc import ABCMeta, abstractmethod


class JWEEncModel(object, metaclass=ABCMeta):
    name: str
    description: str
    algorithm_type = 'JWE'
    algorithm_location = 'enc'

    IV_SIZE: int
    CEK_SIZE: int

    def generate_cek(self) -> bytes:
        return os.urandom(self.CEK_SIZE // 8)

    def generate_iv(self) -> bytes:
        return os.urandom(self.IV_SIZE // 8)

    def check_iv(self, iv: bytes):
        if len(iv) * 8 != self.IV_SIZE:
            raise ValueError('Invalid "iv" size')

    @abstractmethod
    def encrypt(self, msg: bytes, aad: bytes, iv: bytes, key: bytes) -> (bytes, bytes):
        """Encrypt the given "msg" text.

        :param msg: text to be encrypt in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param key: encrypted key in bytes
        :return: (ciphertext, tag)
        """
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, aad: bytes, iv: bytes, tag: bytes, key: bytes) -> bytes:
        """Decrypt the given cipher text.

        :param ciphertext: ciphertext in bytes
        :param aad: additional authenticated data in bytes
        :param iv: initialization vector in bytes
        :param tag: authentication tag in bytes
        :param key: encrypted key in bytes
        :return: message
        """
        pass


class JWEZipModel(object, metaclass=ABCMeta):
    name: str
    description: str
    algorithm_type = 'JWE'
    algorithm_location = 'zip'

    @abstractmethod
    def compress(self, s):
        pass

    @abstractmethod
    def decompress(self, s):
        pass


class JWEAlgModel(object, metaclass=ABCMeta):
    name: str
    description: str
    key_size: Optional[int] = None
    algorithm_type = 'JWE'
    algorithm_location = 'alg'
