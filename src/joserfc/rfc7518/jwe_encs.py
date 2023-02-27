"""
    authlib.jose.rfc7518
    ~~~~~~~~~~~~~~~~~~~~

    Cryptographic Models for Cryptographic Models for Content
    Encryption per `Section 5`_.

    .. _`Section 5`: https://tools.ietf.org/html/rfc7518#section-5
"""
import hmac
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM, CBC
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.exceptions import InvalidTag
from ..rfc7516.models import JWEEncModel
from ..rfc7516.types import EncryptionData
from .util import encode_int


class CBCHS2EncModel(JWEEncModel):
    # The IV used is a 128-bit value generated randomly or
    # pseudo-randomly for use in the cipher.
    IV_SIZE = 128

    def __init__(self, key_size: int, hash_type: int):
        self.name = f'A{key_size}CBC-HS{hash_type}'
        self.description = f'AES_{key_size}_CBC_HMAC_SHA_{hash_type} authenticated encryption algorithm'

        # bit length
        self.key_size = key_size
        # byte length
        self.key_len = key_size // 8

        self.cek_size = key_size * 2
        self.hash_alg = getattr(hashlib, f'sha{hash_type}')

    def _hmac(self, ciphertext: bytes, aad: bytes, iv: bytes, key: bytes) -> bytes:
        al = encode_int(len(aad) * 8, 64)
        msg = aad + iv + ciphertext + al
        d = hmac.new(key, msg, self.hash_alg).digest()
        return d[:self.key_len]

    def encrypt(self,obj: EncryptionData) -> bytes:
        """Key Encryption with AES_CBC_HMAC_SHA2.

        :param obj: encryption data instance
        """
        iv = self.check_iv(obj)
        hkey = obj.cek[:self.key_len]
        ekey = obj.cek[self.key_len:]

        pad = PKCS7(AES.block_size).padder()
        padded_data = pad.update(obj.plaintext) + pad.finalize()

        cipher = Cipher(AES(ekey), CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ciphertext = enc.update(padded_data) + enc.finalize()
        aad = obj.encoded['aad']
        tag = self._hmac(ciphertext, aad, iv, hkey)
        obj.decoded['tag'] = tag
        return ciphertext

    def decrypt(self, obj: EncryptionData) -> bytes:
        """Key Decryption with AES AES_CBC_HMAC_SHA2.

        :param obj: encryption data instance
        :return: payload in bytes
        """
        iv = self.check_iv(obj)
        hkey = obj.cek[:self.key_len]
        dkey = obj.cek[self.key_len:]

        ciphertext = obj.decoded['ciphertext']
        aad = obj.encoded['aad']
        ctag = self._hmac(ciphertext, aad, iv, hkey)
        otag = obj.decoded['tag']
        if not hmac.compare_digest(ctag, otag):
            raise InvalidTag()

        cipher = Cipher(AES(dkey), CBC(iv), backend=default_backend())
        d = cipher.decryptor()
        data = d.update(ciphertext) + d.finalize()
        unpad = PKCS7(AES.block_size).unpadder()
        return unpad.update(data) + unpad.finalize()


class GCMEncModel(JWEEncModel):
    # Use of an IV of size 96 bits is REQUIRED with this algorithm.
    # https://tools.ietf.org/html/rfc7518#section-5.3
    IV_SIZE = 96

    def __init__(self, key_size: int):
        self.name = f'A{key_size}GCM'
        self.description = f'AES GCM using {key_size}-bit key'
        self.key_size = key_size
        self.cek_size = key_size

    def encrypt(self, obj: EncryptionData) -> bytes:
        """Key Encryption with AES GCM

        :param obj: encryption data instance
        """
        iv = self.check_iv(obj)
        cipher = Cipher(AES(obj.cek), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        aad = obj.encoded['aad']
        enc.authenticate_additional_data(aad)
        ciphertext = enc.update(obj.plaintext) + enc.finalize()
        obj.decoded['tag'] = enc.tag
        return ciphertext

    def decrypt(self, obj: EncryptionData) -> bytes:
        """Key Decryption with AES GCM

        :param obj: encryption data instance
        :return: payload in bytes
        """
        iv = self.check_iv(obj)
        tag = obj.decoded['tag']
        cipher = Cipher(AES(obj.cek), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        aad = obj.encoded['aad']
        d.authenticate_additional_data(aad)
        ciphertext = obj.decoded['ciphertext']
        return d.update(ciphertext) + d.finalize()


JWE_ENC_MODELS = [
    CBCHS2EncModel(128, 256),  # A128CBC-HS256
    CBCHS2EncModel(192, 384),  # A192CBC-HS384
    CBCHS2EncModel(256, 512),  # A256CBC-HS512
    GCMEncModel(128),  # A128GCM
    GCMEncModel(192),  # A192GCM
    GCMEncModel(256),  # A256GCM
]
