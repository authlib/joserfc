import os
import struct
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from .rsa_key import RSAKey
from .ec_key import ECKey
from .oct_key import OctKey
from ..rfc7516.models import JWEAlgModel, JWEEncModel
from ..rfc7516.types import EncryptionData, Recipient
from ..util import to_bytes, urlsafe_b64encode, urlsafe_b64decode


class DirectAlgModel(JWEAlgModel):
    name = 'dir'
    description = 'Direct use of a shared symmetric key'

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey, sender_key=None):
        cek = public_key.get_op_key('encrypt')
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        recipient.ek = b''
        obj.cek = cek

    def unwrap(self, enc_alg, ek, headers, key):
        cek = key.get_op_key('decrypt')
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class RSAAlgModel(JWEAlgModel):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

    def __init__(self, name, description, pad_fn):
        self.name = name
        self.description = description
        self.padding = pad_fn
    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: RSAKey, sender_key=None):

        if obj.cek is None:
            obj.cek = enc.generate_cek()

        op_key = public_key.get_op_key('wrapKey')
        if op_key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        recipient.ek = op_key.encrypt(obj.cek, self.padding)

    def unwrap(self, enc_alg, ek, headers, key):
        # it will raise ValueError if failed
        op_key = key.get_op_key('unwrapKey')
        cek = op_key.decrypt(ek, self.padding)
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class AESAlgModel(JWEAlgModel):
    def __init__(self, key_size):
        self.name = 'A{}KW'.format(key_size)
        self.description = 'AES Key Wrap using {}-bit key'.format(key_size)
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey, sender_key=None):

        if obj.cek is None:
            obj.cek = enc.generate_cek()

        op_key = public_key.get_op_key('wrapKey')
        self._check_key(op_key)
        recipient.ek = aes_key_wrap(op_key, obj.cek, default_backend())

    def unwrap(self, enc_alg, ek, headers, key):
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)
        cek = aes_key_unwrap(op_key, ek, default_backend())
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


class AESGCMAlgModel(JWEAlgModel):
    EXTRA_HEADERS = frozenset(['iv', 'tag'])

    def __init__(self, key_size: int):
        self.name = f'A{key_size}GCMKW'
        self.description = f'Key wrapping with AES GCM using {key_size}-bit key'
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey, sender_key=None):

        if obj.cek is None:
            obj.cek = enc.generate_cek()

        op_key = public_key.get_op_key('wrapKey')
        self._check_key(op_key)

        #: https://tools.ietf.org/html/rfc7518#section-4.7.1.1
        #: The "iv" (initialization vector) Header Parameter value is the
        #: base64url-encoded representation of the 96-bit IV value
        iv_size = 96
        iv = os.urandom(iv_size // 8)

        cipher = Cipher(AES(op_key), GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        recipient.ek = enc.update(obj.cek) + enc.finalize()

        header = {
            'iv': urlsafe_b64encode(iv).decode('ascii'),
            'tag': urlsafe_b64encode(enc.tag).decode('ascii')
        }
        obj.protected.update(header)

    def unwrap(self, enc_alg, ek, headers, key):
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)

        iv = headers.get('iv')
        if not iv:
            raise ValueError('Missing "iv" in headers')

        tag = headers.get('tag')
        if not tag:
            raise ValueError('Missing "tag" in headers')

        iv = urlsafe_b64decode(to_bytes(iv))
        tag = urlsafe_b64decode(to_bytes(tag))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        cek = d.update(ek) + d.finalize()
        if len(cek) * 8 != enc_alg.CEK_SIZE:
            raise ValueError('Invalid "cek" length')
        return cek


def u32be_len_input(s, base64=False):
    if not s:
        return b'\x00\x00\x00\x00'
    if base64:
        s = urlsafe_b64decode(to_bytes(s))
    else:
        s = to_bytes(s)
    return struct.pack('>I', len(s)) + s


JWE_ALG_MODELS = [
    DirectAlgModel(),  # dir
    RSAAlgModel('RSA1_5', 'RSAES-PKCS1-v1_5', padding.PKCS1v15()),
    RSAAlgModel(
        'RSA-OAEP', 'RSAES OAEP using default parameters',
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None)),
    RSAAlgModel(
        'RSA-OAEP-256', 'RSAES OAEP using SHA-256 and MGF1 with SHA-256',
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)),

    AESAlgModel(128),  # A128KW
    AESAlgModel(192),  # A192KW
    AESAlgModel(256),  # A256KW
    AESGCMAlgModel(128),  # A128GCMKW
    AESGCMAlgModel(192),  # A192GCMKW
    AESGCMAlgModel(256),  # A256GCMKW
]

# 'PBES2-HS256+A128KW': '',
# 'PBES2-HS384+A192KW': '',
# 'PBES2-HS512+A256KW': '',
