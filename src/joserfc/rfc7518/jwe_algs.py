from __future__ import annotations
from os import urandom
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap,
    aes_key_unwrap,
    InvalidUnwrap,
)
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag
from .derive_key import derive_key_for_concat_kdf
from .oct_key import OctKey
from .rsa_key import RSAKey
from .ec_key import ECKey
from ..rfc7516.models import (
    JWEAlgModel,
    JWEDirectEncryption,
    JWEKeyEncryption,
    JWEKeyWrapping,
    JWEKeyAgreement,
    JWEEncModel,
    Recipient,
)
from ..util import to_bytes, urlsafe_b64encode, urlsafe_b64decode
from ..registry import HeaderParameter
from ..errors import (
    InvalidKeyLengthError,
    DecodeError,
)


class DirectAlgModel(JWEDirectEncryption):
    name = "dir"
    description = "Direct use of a shared symmetric key"
    recommended = True

    def compute_cek(self, size: int, recipient: Recipient[OctKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        cek = key.raw_value
        if len(cek) * 8 != size:
            raise InvalidKeyLengthError(f"A key of size {size} bits MUST be used")
        return cek


class RSAAlgModel(JWEKeyEncryption):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048
    key_types = ["RSA"]

    def __init__(
            self,
            name: str,
            description: str,
            pad_fn: padding.AsymmetricPadding,
            recommended: bool = False):
        self.name = name
        self.description = description
        self.padding = pad_fn
        self.recommended = recommended

    def encrypt_cek(self, cek: bytes, recipient: Recipient[RSAKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("encrypt")
        if op_key.key_size < self.key_size:
            raise InvalidKeyLengthError(f"A key of size {self.key_size} bits or larger MUST be used")
        return op_key.encrypt(cek, self.padding)

    def decrypt_cek(self, recipient: Recipient[RSAKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("decrypt")
        try:
            assert recipient.encrypted_key is not None
            cek = op_key.decrypt(recipient.encrypted_key, self.padding)
        except ValueError as error:
            raise DecodeError(str(error))
        return cek


class AESAlgModel(JWEKeyWrapping):
    def __init__(self, key_size: int, recommended: bool = False):
        self.name = f"A{key_size}KW"
        self.description = f"AES Key Wrap using {key_size}-bit key"
        self.key_size = key_size
        self.recommended = recommended

    def wrap_cek(self, cek: bytes, key: bytes) -> bytes:
        self.check_op_key(key)
        return aes_key_wrap(key, cek, default_backend())

    def unwrap_cek(self, ek: bytes, key: bytes) -> bytes:
        self.check_op_key(key)
        try:
            cek = aes_key_unwrap(key, ek, default_backend())
        except InvalidUnwrap:
            raise DecodeError("Unwrap AES key failed")
        return cek

    def encrypt_cek(self, cek: bytes, recipient: Recipient[OctKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("wrapKey")
        return self.wrap_cek(cek, op_key)

    def decrypt_cek(self, recipient: Recipient[OctKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("unwrapKey")
        assert recipient.encrypted_key is not None
        return self.unwrap_cek(recipient.encrypted_key, op_key)


class AESGCMAlgModel(JWEKeyWrapping):
    more_header_registry = {
        "iv": HeaderParameter("Initialization vector", "str", True),
        "tag": HeaderParameter("Authentication tag", "str", True),
    }

    def __init__(self, key_size: int):
        self.name = f"A{key_size}GCMKW"
        self.description = f"Key wrapping with AES GCM using {key_size}-bit key"
        self.key_size = key_size

    def wrap_cek(self, cek: bytes, key: bytes) -> bytes:  # pragma: no cover
        raise RuntimeError(f"{self.name} can not be used together with Key Agreement")

    def unwrap_cek(self, ek: bytes, key: bytes) -> bytes:  # pragma: no cover
        raise RuntimeError(f"{self.name} can not be used together with Key Agreement")

    def encrypt_cek(self, cek: bytes, recipient: Recipient[OctKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("wrapKey")
        self.check_op_key(op_key)

        #: https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        #: The "iv" (initialization vector) Header Parameter value is the
        #: base64url-encoded representation of the 96-bit IV value
        iv_size = 96
        iv = urandom(iv_size // 8)

        cipher = Cipher(AES(op_key), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()

        encrypted_key = enc.update(cek) + enc.finalize()
        recipient.add_header("iv", urlsafe_b64encode(iv).decode("ascii"))
        recipient.add_header("tag", urlsafe_b64encode(enc.tag).decode("ascii"))
        return encrypted_key

    def decrypt_cek(self, recipient: Recipient[OctKey]) -> bytes:
        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        op_key = key.get_op_key("unwrapKey")
        self.check_op_key(op_key)

        headers = recipient.headers()
        assert "iv" in headers
        assert "tag" in headers
        iv = urlsafe_b64decode(to_bytes(headers["iv"]))
        tag = urlsafe_b64decode(to_bytes(headers["tag"]))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        try:
            assert recipient.encrypted_key is not None
            cek = d.update(recipient.encrypted_key) + d.finalize()
        except InvalidTag as error:
            raise DecodeError(str(error))
        return cek


class ECDHESAlgModel(JWEKeyAgreement):
    key_types = ["EC", "OKP"]
    more_header_registry = {
        "epk": HeaderParameter("Ephemeral Public Key", "jwk", True),
        "apu": HeaderParameter("Agreement PartyUInfo", "str"),
        "apv": HeaderParameter("Agreement PartyVInfo", "str"),
    }

    # https://tools.ietf.org/html/rfc7518#section-4.6
    def __init__(self, key_wrapping: JWEKeyWrapping | None = None):
        if key_wrapping is None:
            self.name = "ECDH-ES"
            self.description = "ECDH-ES in the Direct Key Agreement mode"
            self.key_size = None
            self.recommended = True
        else:
            self.name = f"ECDH-ES+{key_wrapping.name}"
            self.description = f"ECDH-ES using Concat KDF and CEK wrapped with {key_wrapping.name}"
            self.key_size = key_wrapping.key_size
            self.recommended = key_wrapping.recommended
        self.key_wrapping = key_wrapping

    def encrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient[ECKey]) -> bytes:
        recipient_key = recipient.recipient_key
        assert recipient_key is not None

        ephemeral_key = recipient.ephemeral_key
        assert ephemeral_key is not None

        shared_key = ephemeral_key.exchange_derive_key(recipient_key)
        headers = recipient.headers()
        return derive_key_for_concat_kdf(shared_key, headers, enc.cek_size, self.key_size)

    def decrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient[ECKey]) -> bytes:
        headers = recipient.headers()
        assert "epk" in headers

        recipient_key = recipient.recipient_key
        assert recipient_key is not None

        self.check_key_type(recipient_key)
        ephemeral_key = recipient_key.import_key(headers["epk"])
        shared_key = recipient_key.exchange_derive_key(ephemeral_key)
        return derive_key_for_concat_kdf(shared_key, headers, enc.cek_size, self.key_size)


class PBES2HSAlgModel(JWEKeyEncryption):
    # https://www.rfc-editor.org/rfc/rfc7518#section-4.8
    key_size: int
    more_header_registry = {
        "p2s": HeaderParameter("PBES2 Salt Input", "str", True),
        "p2c": HeaderParameter("PBES2 Count", "int", True),
    }
    key_types = ["oct"]

    # A minimum iteration count of 1000 is RECOMMENDED.
    DEFAULT_P2C = 2048

    def __init__(self, hash_size: int, key_wrapping: JWEKeyWrapping):
        self.name = f"PBES2-HS{hash_size}+{key_wrapping.name}"
        self.description = f"PBES2 with HMAC SHA-{hash_size} and {key_wrapping.name} wrapping"
        self.key_size = key_wrapping.key_size
        self.key_wrapping = key_wrapping
        self.hash_alg = getattr(hashes, f"SHA{hash_size}")()

    def compute_derived_key(self, key: bytes, p2s: bytes, p2c: int) -> bytes:
        # The salt value used is (UTF8(Alg) || 0x00 || Salt Input)
        salt = to_bytes(self.name) + b"\x00" + p2s
        kdf = PBKDF2HMAC(
            algorithm=self.hash_alg,
            length=self.key_size // 8,
            salt=salt,
            iterations=p2c,
            backend=default_backend(),
        )
        return kdf.derive(key)

    def encrypt_cek(self, cek: bytes, recipient: Recipient[OctKey]) -> bytes:
        headers = recipient.headers()
        if "p2s" not in headers:
            p2s = urandom(16)
            recipient.add_header("p2s", urlsafe_b64encode(p2s).decode("ascii"))
        else:
            p2s = urlsafe_b64decode(to_bytes(headers["p2s"]))

        if "p2c" not in headers:
            # A minimum iteration count of 1000 is RECOMMENDED.
            p2c = self.DEFAULT_P2C
            recipient.add_header("p2c", p2c)
        else:
            p2c = headers["p2c"]

        key = recipient.recipient_key
        assert key is not None
        self.check_key_type(key)
        kek = self.compute_derived_key(key.get_op_key("deriveKey"), p2s, p2c)
        return self.key_wrapping.wrap_cek(cek, kek)

    def decrypt_cek(self, recipient: Recipient[OctKey]) -> bytes:
        headers = recipient.headers()
        assert "p2s" in headers
        assert "p2c" in headers
        p2s = urlsafe_b64decode(to_bytes(headers["p2s"]))
        p2c = headers["p2c"]

        key = recipient.recipient_key
        assert key is not None

        self.check_key_type(key)
        kek = self.compute_derived_key(key.get_op_key("deriveKey"), p2s, p2c)
        assert recipient.encrypted_key is not None
        return self.key_wrapping.unwrap_cek(recipient.encrypted_key, kek)


A128KW = AESAlgModel(128, True)  # A128KW, Recommended
A192KW = AESAlgModel(192)  # A192KW
A256KW = AESAlgModel(256, True)  # A256KW, Recommended


#: https://www.rfc-editor.org/rfc/rfc7518#section-4.1
JWE_ALG_MODELS: list[JWEAlgModel] = [
    # Avoid all RSA-PKCS1 v1.5 encryption algorithms ([RFC8017], Section 7.2),
    # preferring RSAES-OAEP ([RFC8017], Section 7.1).
    # https://www.rfc-editor.org/rfc/rfc8725#section-3.2
    RSAAlgModel("RSA1_5", "RSAES-PKCS1-v1_5", padding.PKCS1v15()),
    RSAAlgModel(
        "RSA-OAEP",
        "RSAES OAEP using default parameters",
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None),
        True,
    ),  # Recommended+
    RSAAlgModel(
        "RSA-OAEP-256",
        "RSAES OAEP using SHA-256 and MGF1 with SHA-256",
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None),
    ),
    A128KW,
    A192KW,
    A256KW,
    DirectAlgModel(),  # dir, Recommended
    ECDHESAlgModel(None),  # ECDH-ES, Recommended+
    ECDHESAlgModel(A128KW),  # ECDH-ES+A128KW, Recommended
    ECDHESAlgModel(A192KW),  # ECDH-ES+A192KW
    ECDHESAlgModel(A256KW),  # ECDH-ES+A256KW, Recommended
    AESGCMAlgModel(128),  # A128GCMKW
    AESGCMAlgModel(192),  # A192GCMKW
    AESGCMAlgModel(256),  # A256GCMKW
    PBES2HSAlgModel(256, A128KW),  # PBES2-HS256+A128KW
    PBES2HSAlgModel(384, A192KW),  # PBES2-HS384+A192KW
    PBES2HSAlgModel(512, A256KW),  # PBES2-HS512+A256KW
]
