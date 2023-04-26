from Cryptodome.Cipher import ChaCha20_Poly1305
from ..rfc7516.models import JWEEncModel
from ..rfc7516.types import EncryptionData


class ChaCha20EncModel(JWEEncModel):
    cek_size = 256
    recommended: bool = False

    def __init__(self, name: str, description: str, iv_size: int):
        self.name = name
        self.description = description
        self.IV_SIZE = iv_size

    def encrypt(self, obj: EncryptionData) -> bytes:
        """Key Encryption with AEAD_CHACHA20_POLY1305

        :param obj: encryption data instance
        """
        iv = self.check_iv(obj)
        aad = obj.encoded["aad"]

        chacha = ChaCha20_Poly1305.new(key=obj.cek, nonce=iv)
        chacha.update(aad)
        ciphertext, tag = chacha.encrypt_and_digest(obj.plaintext)
        obj.decoded["tag"] = tag
        return ciphertext

    def decrypt(self, obj: EncryptionData) -> bytes:
        """Key Decryption with AEAD_CHACHA20_POLY1305

        :param obj: encryption data instance
        :return: payload in bytes
        """
        iv = self.check_iv(obj)
        aad = obj.encoded["aad"]
        tag = obj.decoded["tag"]
        ciphertext = obj.decoded["ciphertext"]
        chacha = ChaCha20_Poly1305.new(key=obj.cek, nonce=iv)
        chacha.update(aad)
        return chacha.decrypt_and_verify(ciphertext, tag)

C20P = ChaCha20EncModel("C20P", "ChaCha20-Poly1305", 96)
XC20P = ChaCha20EncModel("XC20P", "XChaCha20-Poly1305", 192)

JWE_ENC_MODELS = [C20P, XC20P]
