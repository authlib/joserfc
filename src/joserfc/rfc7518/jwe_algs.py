import os
import struct
import typing as t
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .rsa_key import RSAKey
from .oct_key import OctKey
from ..rfc7516.models import JWEAlgModel, JWEEncModel, EncryptionData, Recipient
from ..rfc7517.models import CurveKey
from ..util import to_bytes, urlsafe_b64encode, urlsafe_b64decode, u32be_len_input
from ..registry import Header, HeaderParameter, is_str, is_int, is_jwk


class DirectAlgModel(JWEAlgModel):
    name = "dir"
    description = "Direct use of a shared symmetric key"
    recommended = True

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        obj: EncryptionData = recipient.parent
        assert obj.cek is None

        cek = key.get_op_key("encrypt")
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')

        # attach CEK to parent
        obj.cek = cek
        return b""

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        cek = key.get_op_key("decrypt")
        return cek


class RSAAlgModel(JWEAlgModel):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

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

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: RSAKey) -> bytes:
        op_key = key.get_op_key("encrypt")
        if op_key.key_size < self.key_size:
            raise ValueError("A key of size 2048 bits or larger MUST be used")
        return op_key.encrypt(recipient.parent.cek, self.padding)

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: RSAKey) -> bytes:
        op_key = key.get_op_key("decrypt")
        cek = op_key.decrypt(recipient.encrypted_key, self.padding)
        return cek


class AESAlgModel(JWEAlgModel):
    def __init__(self, key_size: int, recommended: bool = False):
        self.name = f"A{key_size}KW"
        self.description = f"AES Key Wrap using {key_size}-bit key"
        self.key_size = key_size
        self.recommended = recommended

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError("A key of size {} bits is required.".format(self.key_size))

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key("wrapKey")
        self._check_key(op_key)
        cek = recipient.parent.cek
        return aes_key_wrap(op_key, cek, default_backend())

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key("unwrapKey")
        self._check_key(op_key)
        cek = aes_key_unwrap(op_key, recipient.encrypted_key, default_backend())
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        return cek


class AESGCMAlgModel(JWEAlgModel):
    more_header_registry = {
        "iv": HeaderParameter("Initialization vector", True, is_str),
        "tag": HeaderParameter("Authentication tag", True, is_str),
    }

    def __init__(self, key_size: int):
        self.name = f"A{key_size}GCMKW"
        self.description = f"Key wrapping with AES GCM using {key_size}-bit key"
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError("A key of size {} bits is required.".format(self.key_size))

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key("wrapKey")
        self._check_key(op_key)

        #: https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        #: The "iv" (initialization vector) Header Parameter value is the
        #: base64url-encoded representation of the 96-bit IV value
        iv_size = 96
        iv = os.urandom(iv_size // 8)

        cipher = Cipher(AES(op_key), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        obj: EncryptionData = recipient.parent

        encrypted_key = enc.update(obj.cek) + enc.finalize()
        recipient.add_header("iv", urlsafe_b64encode(iv).decode("ascii"))
        recipient.add_header("tag", urlsafe_b64encode(enc.tag).decode("ascii"))
        return encrypted_key

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key("unwrapKey")
        self._check_key(op_key)

        headers = recipient.headers()
        assert "iv" in headers
        assert "tag" in headers
        iv = urlsafe_b64decode(to_bytes(headers["iv"]))
        tag = urlsafe_b64decode(to_bytes(headers["tag"]))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        cek = d.update(recipient.encrypted_key) + d.finalize()
        return cek


class ECDHESAlgModel(JWEAlgModel):
    more_header_registry = {
        "epk": HeaderParameter("Ephemeral Public Key", True, is_jwk),
        "apu": HeaderParameter("Agreement PartyUInfo", False, is_str),
        "apv": HeaderParameter("Agreement PartyVInfo", False, is_str),
    }

    # https://tools.ietf.org/html/rfc7518#section-4.6
    def __init__(self, key_wrapping: t.Optional[JWEAlgModel] = None):
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

    @property
    def wrapped_key_mode(self) -> bool:
        return self.key_wrapping is not None

    def get_bit_size(self, enc: JWEEncModel) -> int:
        if self.key_size is None:
            bit_size = enc.cek_size
        else:
            bit_size = self.key_size
        return bit_size

    def compute_derived_key(self, shared_key: bytes, header: Header, bit_size: int):
        fixed_info = compute_concat_kdf_info(self.direct_key_mode, header, bit_size)
        return compute_derived_key_for_concat_kdf(shared_key, bit_size, fixed_info)

    def prepare_recipient_header(self, enc: JWEEncModel, recipient: Recipient, key: CurveKey):
        if recipient.ephemeral_key is None:
            recipient.ephemeral_key = key.generate_key(key.curve_name, private=True)
        recipient.add_header("epk", recipient.ephemeral_key.as_dict(private=False))

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: CurveKey) -> bytes:
        if not self.wrapped_key_mode:
            self.prepare_recipient_header(enc, recipient, key)

        bit_size = self.get_bit_size(enc)
        pubkey = key.get_op_key("deriveKey")
        shared_key = recipient.ephemeral_key.exchange_shared_key(pubkey)
        dk = self.compute_derived_key(shared_key, recipient.headers(), bit_size)
        if self.key_wrapping:
            return self.key_wrapping.encrypt_recipient(enc, recipient, OctKey.import_key(dk))

        obj: EncryptionData = recipient.parent
        assert obj.cek is None
        obj.cek = dk
        return b""

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: CurveKey) -> bytes:
        headers = recipient.headers()
        assert "epk" in headers
        epk = key.import_key(headers["epk"])

        bit_size = self.get_bit_size(enc)
        pubkey = epk.get_op_key("deriveKey")
        shared_key = key.exchange_shared_key(pubkey)
        dk = self.compute_derived_key(shared_key, headers, bit_size)

        if self.key_wrapping:
            return self.key_wrapping.decrypt_recipient(enc, recipient, OctKey.import_key(dk))
        return dk


class PBES2HSAlgModel(JWEAlgModel):
    # https://www.rfc-editor.org/rfc/rfc7518#section-4.8
    more_header_registry = {
        "p2s": HeaderParameter("PBES2 Salt Input", True, is_str),
        "p2c": HeaderParameter("PBES2 Count", True, is_int),
    }

    # A minimum iteration count of 1000 is RECOMMENDED.
    DEFAULT_P2C = 2048

    def __init__(self, hash_size: int, key_wrapping: JWEAlgModel):
        self.name = f"PBES2-HS{hash_size}+{key_wrapping.name}"
        self.description = f"PBES2 with HMAC SHA-{hash_size} and {key_wrapping.name} wrapping"
        self.key_size = key_wrapping.key_size
        self.key_wrapping = key_wrapping
        self.hash_alg = getattr(hashes, f"SHA{hash_size}")()

    @property
    def wrapped_key_mode(self) -> bool:
        return True

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

    def prepare_recipient_header(self, enc: JWEEncModel, recipient: Recipient, key: OctKey):
        headers = recipient.headers()

        if "p2s" not in headers:
            p2s = os.urandom(16)
            recipient.add_header("p2s", urlsafe_b64encode(p2s).decode("ascii"))

        if "p2c" not in headers:
            # A minimum iteration count of 1000 is RECOMMENDED.
            p2c = self.DEFAULT_P2C
            recipient.add_header("p2c", p2c)

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        headers = recipient.headers()
        p2s = urlsafe_b64decode(to_bytes(headers["p2s"]))
        p2c = headers["p2c"]
        kek = self.compute_derived_key(key.get_op_key("deriveKey"), p2s, p2c)
        return self.key_wrapping.encrypt_recipient(enc, recipient, OctKey.import_key(kek))

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        headers = recipient.headers()
        assert "p2s" in headers
        assert "p2c" in headers
        p2s = urlsafe_b64decode(to_bytes(headers["p2s"]))
        p2c = headers["p2c"]
        kek = self.compute_derived_key(key.get_op_key("deriveKey"), p2s, p2c)
        return self.key_wrapping.decrypt_recipient(enc, recipient, OctKey.import_key(kek))


def compute_concat_kdf_info(direct_key_mode: bool, header: Header, bit_size: int):
    # AlgorithmID
    if direct_key_mode:
        alg_id = u32be_len_input(header["enc"])
    else:
        alg_id = u32be_len_input(header["alg"])

    # PartyUInfo
    apu_info = u32be_len_input(header.get("apu"), True)
    # PartyVInfo
    apv_info = u32be_len_input(header.get("apv"), True)
    # SuppPubInfo
    pub_info = struct.pack(">I", bit_size)
    return alg_id + apu_info + apv_info + pub_info


def compute_derived_key_for_concat_kdf(shared_key: bytes, bit_size: int, otherinfo: bytes):
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=bit_size // 8,
        otherinfo=otherinfo,
        backend=default_backend(),
    )
    return ckdf.derive(shared_key)


A128KW = AESAlgModel(128, True)  # A128KW, Recommended
A192KW = AESAlgModel(192)  # A192KW
A256KW = AESAlgModel(256, True)  # A256KW, Recommended


#: https://www.rfc-editor.org/rfc/rfc7518#section-4.1
JWE_ALG_MODELS = [
    RSAAlgModel("RSA1_5", "RSAES-PKCS1-v1_5", padding.PKCS1v15()),  # Recommended-
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
