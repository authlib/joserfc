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
from ..rfc7516.models import JWEAlgModel, JWEEncModel
from ..rfc7516.types import EncryptionData, Recipient, Header
from ..rfc7517.models import CurveKey
from ..util import to_bytes, urlsafe_b64encode, urlsafe_b64decode
from ..registry import HeaderParameter, is_str, is_int, is_jwk


class DirectAlgModel(JWEAlgModel):
    name = 'dir'
    description = 'Direct use of a shared symmetric key'
    recommended = True
    key_encryption = True

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        obj: EncryptionData = recipient.parent
        assert obj.cek is None

        cek = key.get_op_key('encrypt')
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')

        # attach CEK to parent
        obj.cek = cek
        return b''

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        cek = key.get_op_key('decrypt')
        return cek


class RSAAlgModel(JWEAlgModel):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048
    key_encryption = True

    def __init__(self, name: str, description: str,
                 pad_fn: padding.AsymmetricPadding,
                 recommended: bool=False):
        self.name = name
        self.description = description
        self.padding = pad_fn
        self.recommended = recommended

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: RSAKey) -> bytes:
        op_key = key.get_op_key('encrypt')
        if op_key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        return op_key.encrypt(recipient.parent.cek, self.padding)

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: RSAKey) -> bytes:
        op_key = key.get_op_key('decrypt')
        cek = op_key.decrypt(recipient.encrypted_key, self.padding)
        return cek


class AESAlgModel(JWEAlgModel):
    key_wrapping = True

    def __init__(self, key_size: int, recommended: bool=False):
        self.name = f'A{key_size}KW'
        self.description = f'AES Key Wrap using {key_size}-bit key'
        self.key_size = key_size
        self.recommended = recommended

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap_cek(self, cek: bytes, key: OctKey) -> bytes:
        op_key = key.get_op_key('wrapKey')
        self._check_key(op_key)
        return aes_key_wrap(op_key, cek, default_backend())

    def unwrap_cek(self, encrypted_key: bytes, key: OctKey) -> bytes:
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)
        return aes_key_unwrap(op_key, encrypted_key, default_backend())

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        return self.wrap_cek(recipient.parent.cek, key)

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        cek = self.unwrap_cek(recipient.encrypted_key, key)
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        return cek


A128KW = AESAlgModel(128, True)  # A128KW, Recommended
A192KW = AESAlgModel(192)  # A192KW
A256KW = AESAlgModel(256, True)  # A256KW, Recommended

AES_KW_MAP: t.Dict[int, AESAlgModel] = {
    128: A128KW,
    192: A192KW,
    256: A256KW,
}

class AESGCMAlgModel(JWEAlgModel):
    more_header_registry = {
        'iv': HeaderParameter('Initialization vector', True, is_str),
        'tag': HeaderParameter('Authentication tag', True, is_str),
    }
    key_wrapping = True

    def __init__(self, key_size: int):
        self.name = f'A{key_size}GCMKW'
        self.description = f'Key wrapping with AES GCM using {key_size}-bit key'
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key('wrapKey')
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
        recipient.add_header('iv', urlsafe_b64encode(iv).decode('ascii'))
        recipient.add_header('tag', urlsafe_b64encode(enc.tag).decode('ascii'))
        return encrypted_key

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        op_key = key.get_op_key('unwrapKey')
        self._check_key(op_key)

        headers = recipient.headers()
        assert 'iv' in headers
        assert 'tag' in headers
        iv = urlsafe_b64decode(to_bytes(headers['iv']))
        tag = urlsafe_b64decode(to_bytes(headers['tag']))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        cek = d.update(recipient.encrypted_key) + d.finalize()
        return cek


class ECDHESAlgModel(JWEAlgModel):
    more_header_registry = {
        'epk': HeaderParameter('Ephemeral Public Key', True, is_jwk),
        'apu': HeaderParameter('Agreement PartyUInfo', False, is_str),
        'apv': HeaderParameter('Agreement PartyVInfo', False, is_str),
    }
    key_agreement = True

    # https://tools.ietf.org/html/rfc7518#section-4.6
    def __init__(self, key_size: t.Optional[int]=None, recommended: bool=False):
        if key_size is None:
            self.name = 'ECDH-ES'
            self.description = 'ECDH-ES in the Direct Key Agreement mode'
            self.key_wrapping = False
        else:
            self.name = f'ECDH-ES+A{key_size}KW'
            self.description = f'ECDH-ES using Concat KDF and CEK wrapped with A{key_size}KW'
            self.key_wrapping = True
        self.key_size = key_size
        self.recommended = recommended

    def get_bit_size(self, enc: JWEEncModel) -> int:
        if self.key_size is None:
            bit_size = enc.cek_size
        else:
            bit_size = self.key_size
        return bit_size

    def compute_fixed_info(self, header: Header, bit_size: int):
        # AlgorithmID
        if self.key_size is None:
            alg_id = u32be_len_input(header['enc'])
        else:
            alg_id = u32be_len_input(header['alg'])

        # PartyUInfo
        apu_info = u32be_len_input(header.get('apu'), True)
        # PartyVInfo
        apv_info = u32be_len_input(header.get('apv'), True)
        # SuppPubInfo
        pub_info = struct.pack('>I', bit_size)
        return alg_id + apu_info + apv_info + pub_info

    def compute_derived_key(self, shared_key: bytes, header: Header, bit_size: int) -> bytes:
        fixed_info = self.compute_fixed_info(header, bit_size)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=bit_size // 8,
            otherinfo=fixed_info,
            backend=default_backend()
        )
        return ckdf.derive(shared_key)

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: CurveKey) -> bytes:
        if recipient.ephemeral_key is None:
            recipient.ephemeral_key = key.generate_key(key.curve_name, private=True)

        bit_size = self.get_bit_size(enc)
        pubkey = key.get_op_key('deriveKey')
        shared_key = recipient.ephemeral_key.exchange_shared_key(pubkey)
        headers = recipient.headers()
        dk = self.compute_derived_key(shared_key, headers, bit_size)

        obj: EncryptionData = recipient.parent
        recipient.add_header('epk', recipient.ephemeral_key.as_dict(private=False))

        if self.key_size is None:
            assert obj.cek is None
            obj.cek = dk
            return b''
        else:
            aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
            return aeskw.wrap_cek(obj.cek, OctKey.import_key(dk))

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: CurveKey) -> bytes:
        headers = recipient.headers()
        assert 'epk' in headers
        epk = key.import_key(headers['epk'])

        bit_size = self.get_bit_size(enc)
        pubkey = epk.get_op_key('deriveKey')
        shared_key = key.exchange_shared_key(pubkey)

        dk = self.compute_derived_key(shared_key, headers, bit_size)
        if self.key_size is None:
            # delivery_key is ciphertext's encrypt key
            return dk
        else:
            aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
            return aeskw.unwrap_cek(recipient.encrypted_key, OctKey.import_key(dk))


class PBES2HSAlgModel(JWEAlgModel):
    # https://www.rfc-editor.org/rfc/rfc7518#section-4.8
    more_header_registry = {
        'p2s': HeaderParameter('PBES2 Salt Input', True, is_str),
        'p2c': HeaderParameter('PBES2 Count', True, is_int),
    }
    key_wrapping = True

    # A minimum iteration count of 1000 is RECOMMENDED.
    DEFAULT_P2C = 2048

    def __init__(self, hash_size: int, key_size: int):
        self.name = f'PBES2-HS{hash_size}+A{key_size}KW'
        self.description = f'PBES2 with HMAC SHA-{hash_size} and A{key_size}KW wrapping'
        self.key_size = key_size
        self.hash_alg = getattr(hashes, f'SHA{hash_size}')()

    def compute_derived_key(self, key: bytes, header: Header, p2c: int) -> bytes:
        p2s = urlsafe_b64decode(to_bytes(header['p2s']))
        # The salt value used is (UTF8(Alg) || 0x00 || Salt Input)
        salt = to_bytes(self.name) + b'\x00' + p2s
        kdf = PBKDF2HMAC(
            algorithm=self.hash_alg,
            length=self.key_size // 8,
            salt=salt,
            iterations=p2c,
            backend=default_backend(),
        )
        return kdf.derive(key)

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        obj: EncryptionData = recipient.parent
        headers = recipient.headers()

        if 'p2s' not in headers:
            p2s = os.urandom(16)
            recipient.add_header('p2s', urlsafe_b64encode(p2s).decode('ascii'))

        if 'p2c' in headers:
            p2c = headers['p2c']
        else:
            # A minimum iteration count of 1000 is RECOMMENDED.
            p2c = self.DEFAULT_P2C
            recipient.add_header('p2c', p2c)

        kek = self.compute_derived_key(key.get_op_key('deriveKey'), headers, p2c)
        aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
        return aeskw.wrap_cek(obj.cek, OctKey.import_key(kek))

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, key: OctKey) -> bytes:
        headers = recipient.headers()
        obj: EncryptionData = recipient.parent

        assert 'p2s' in headers
        assert 'p2c' in headers

        p2c = headers['p2c']
        kek = self.compute_derived_key(key.get_op_key('deriveKey'), headers, p2c)
        aeskw = AES_KW_MAP[self.key_size]
        return aeskw.unwrap_cek(recipient.encrypted_key, OctKey.import_key(kek))


def u32be_len_input(s, base64=False):
    if not s:
        return b'\x00\x00\x00\x00'
    if base64:
        s = urlsafe_b64decode(to_bytes(s))
    else:
        s = to_bytes(s)
    return struct.pack('>I', len(s)) + s


#: https://www.rfc-editor.org/rfc/rfc7518#section-4.1
JWE_ALG_MODELS = [
    RSAAlgModel('RSA1_5', 'RSAES-PKCS1-v1_5', padding.PKCS1v15()),  # Recommended-
    RSAAlgModel(
        'RSA-OAEP', 'RSAES OAEP using default parameters',
        padding.OAEP(padding.MGF1(hashes.SHA1()), hashes.SHA1(), None),
        True,
    ),   # Recommended+
    RSAAlgModel(
        'RSA-OAEP-256', 'RSAES OAEP using SHA-256 and MGF1 with SHA-256',
        padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)
    ),
    A128KW,
    A192KW,
    A256KW,
    DirectAlgModel(),  # dir, Recommended
    ECDHESAlgModel(None),  # ECDH-ES, Recommended+
    ECDHESAlgModel(128, True),  # ECDH-ES+A128KW, Recommended
    ECDHESAlgModel(192),  # ECDH-ES+A192KW
    ECDHESAlgModel(256, True),  # ECDH-ES+A256KW, Recommended
    AESGCMAlgModel(128),  # A128GCMKW
    AESGCMAlgModel(192),  # A192GCMKW
    AESGCMAlgModel(256),  # A256GCMKW
    PBES2HSAlgModel(256, 128),  # PBES2-HS256+A128KW
    PBES2HSAlgModel(384, 192),  # PBES2-HS384+A192KW
    PBES2HSAlgModel(512, 256),  # PBES2-HS512+A256KW
]
