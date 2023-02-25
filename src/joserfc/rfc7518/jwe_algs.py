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
from ..rfc7517.keys import CurveKey
from ..util import to_bytes, urlsafe_b64encode, urlsafe_b64decode
from ..registry import HeaderParameter, is_str, is_int, is_jwk


class DirectAlgModel(JWEAlgModel):
    name = 'dir'
    description = 'Direct use of a shared symmetric key'
    recommended = True

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey) -> EncryptionData:
        cek = public_key.get_op_key('encrypt')
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        recipient.ek = b''
        obj.cek = cek
        return obj

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: OctKey) -> bytes:
        cek = private_key.get_op_key('decrypt')
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        return cek


class RSAAlgModel(JWEAlgModel):
    #: A key of size 2048 bits or larger MUST be used with these algorithms
    #: RSA1_5, RSA-OAEP, RSA-OAEP-256
    key_size = 2048

    def __init__(self, name: str, description: str,
                 pad_fn: padding.AsymmetricPadding,
                 recommended: bool=False):
        self.name = name
        self.description = description
        self.padding = pad_fn
        self.recommended = recommended

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: RSAKey) -> EncryptionData:
        op_key = public_key.get_op_key('wrapKey')
        if op_key.key_size < self.key_size:
            raise ValueError('A key of size 2048 bits or larger MUST be used')
        recipient.ek = op_key.encrypt(obj.cek, self.padding)
        return obj

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: RSAKey) -> bytes:
        # it will raise ValueError if failed
        op_key = private_key.get_op_key('unwrapKey')
        cek = op_key.decrypt(recipient.ek, self.padding)
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        return cek


class AESAlgModel(JWEAlgModel):
    def __init__(self, key_size: int, recommended: bool=False):
        self.name = f'A{key_size}KW'
        self.description = f'AES Key Wrap using {key_size}-bit key'
        self.key_size = key_size
        self.recommended = recommended

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey) -> EncryptionData:
        op_key = public_key.get_op_key('wrapKey')
        self._check_key(op_key)
        recipient.ek = aes_key_wrap(op_key, obj.cek, default_backend())
        return obj

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: OctKey) -> bytes:
        op_key = private_key.get_op_key('unwrapKey')
        self._check_key(op_key)
        cek = aes_key_unwrap(op_key, recipient.ek, default_backend())
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
    more_header = {
        'iv': HeaderParameter('Initialization vector', True, is_str),
        'tag': HeaderParameter('Authentication tag', True, is_str),
    }

    def __init__(self, key_size: int):
        self.name = f'A{key_size}GCMKW'
        self.description = f'Key wrapping with AES GCM using {key_size}-bit key'
        self.key_size = key_size

    def _check_key(self, key):
        if len(key) * 8 != self.key_size:
            raise ValueError(
                'A key of size {} bits is required.'.format(self.key_size))

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey) -> EncryptionData:

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
        return obj

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: OctKey) -> bytes:
        # def unwrap(self, enc_alg, ek, headers, key):
        op_key = private_key.get_op_key('unwrapKey')
        self._check_key(op_key)

        iv = urlsafe_b64decode(to_bytes(obj.protected['iv']))
        tag = urlsafe_b64decode(to_bytes(obj.protected['tag']))

        cipher = Cipher(AES(op_key), GCM(iv, tag), backend=default_backend())
        d = cipher.decryptor()
        cek = d.update(recipient.ek) + d.finalize()
        if len(cek) * 8 != enc.cek_size:
            raise ValueError('Invalid "cek" length')
        return cek


class ECDHESAlgModel(JWEAlgModel):
    more_header = {
        'epk': HeaderParameter('Ephemeral Public Key', True, is_jwk),
        'apu': HeaderParameter('Agreement PartyUInfo', False, is_str),
        'apv': HeaderParameter('Agreement PartyVInfo', False, is_str),
    }

    # https://tools.ietf.org/html/rfc7518#section-4.6
    def __init__(self, key_size: t.Optional[int]=None, recommended: bool=False):
        if key_size is None:
            self.name = 'ECDH-ES'
            self.description = 'ECDH-ES in the Direct Key Agreement mode'
        else:
            self.name = f'ECDH-ES+A{key_size}KW'
            self.description = f'ECDH-ES using Concat KDF and CEK wrapped with A{key_size}KW'
        self.key_size = key_size
        self.recommended = recommended

    def get_bit_size(self, enc: JWEEncModel) -> int:
        if self.key_size is None:
            bit_size = enc.cek_size
        else:
            bit_size = self.key_size
        return bit_size

    def compute_fixed_info(self, protected: Header, bit_size: int):
        # AlgorithmID
        if self.key_size is None:
            alg_id = u32be_len_input(protected['enc'])
        else:
            alg_id = u32be_len_input(protected['alg'])

        # PartyUInfo
        apu_info = u32be_len_input(protected.get('apu'), True)
        # PartyVInfo
        apv_info = u32be_len_input(protected.get('apv'), True)
        # SuppPubInfo
        pub_info = struct.pack('>I', bit_size)
        return alg_id + apu_info + apv_info + pub_info

    def deliver(self, private_key: CurveKey, public_key: CurveKey, protected: Header, bit_size: int) -> bytes:
        pubkey = public_key.get_op_key('wrapKey')
        shared_key = private_key.exchange_shared_key(pubkey)
        fixed_info = self.compute_fixed_info(protected, bit_size)
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=bit_size // 8,
            otherinfo=fixed_info,
            backend=default_backend()
        )
        return ckdf.derive(shared_key)

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: CurveKey) -> EncryptionData:

        if recipient.epk is None:
            recipient.epk = public_key.generate_key(public_key.curve_name, private=True)

        bit_size = self.get_bit_size(enc)
        deliver_key = self.deliver(recipient.epk, public_key, obj.protected, bit_size)

        obj.protected.update({'epk': recipient.epk.as_dict(private=False)})
        if self.key_size is None:
            recipient.ek = b''
            obj.cek = deliver_key
        else:
            aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
            aeskw.wrap(enc, obj, recipient, OctKey.import_key(deliver_key))
        return obj

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: CurveKey) -> bytes:
        bit_size = self.get_bit_size(enc)
        epk = private_key.import_key(obj.protected['epk'])
        delivery_key = self.deliver(private_key, epk, obj.protected, bit_size)
        if self.key_size is None:
            # delivery_key is ciphertext's encrypt key
            return delivery_key

        wrap_key = OctKey.import_key(delivery_key)
        aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
        return aeskw.unwrap(enc, obj, recipient, wrap_key)


class PBES2HSAlgModel(JWEAlgModel):
    # https://www.rfc-editor.org/rfc/rfc7518#section-4.8
    more_header = {
        'p2s': HeaderParameter('PBES2 Salt Input', True, is_str),
        'p2c': HeaderParameter('PBES2 Count', True, is_int),
    }

    DEFAULT_P2C = 2048

    def __init__(self, hash_size: int, key_size: int):
        self.name = f'PBES2-HS{hash_size}+A{key_size}KW'
        self.description = f'PBES2 with HMAC SHA-{hash_size} and A{key_size}KW wrapping'
        self.key_size = key_size
        self.hash_alg = getattr(hashes, f'SHA{hash_size}')()

    def get_aes_key(self, key: bytes, p2s: bytes, p2c: int) -> OctKey:
        # The salt value used is (UTF8(Alg) || 0x00 || Salt Input)
        salt = to_bytes(self.name) + b'\x00' + p2s
        kdf = PBKDF2HMAC(
            algorithm=self.hash_alg,
            length=self.key_size // 8,
            salt=salt,
            iterations=p2c,
            backend=default_backend(),
        )
        dk = kdf.derive(key)
        return OctKey.import_key(dk, {'use': 'enc'})

    @staticmethod
    def _get_p2s(obj: EncryptionData) -> bytes:
        if 'p2s' in obj.protected:
            p2s = urlsafe_b64decode(to_bytes(obj.protected['p2s']))
            if len(p2s) < 8:
                raise ValueError('PBES2 Salt Input must be 8 or more octets')
        else:
            p2s = os.urandom(16)
            obj.protected['p2s'] = urlsafe_b64encode(p2s)
        return p2s

    def wrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
             public_key: OctKey) -> EncryptionData:

        p2s = getattr(obj, '_p2s', None)
        if p2s is None:
            p2s = self._get_p2s(obj)
            setattr(obj, '_p2s', p2s)

        if 'p2c' in obj.protected:
            p2c = obj.protected['p2c']
        else:
            # A minimum iteration count of 1000 is RECOMMENDED.
            p2c = self.DEFAULT_P2C
            obj.protected['p2c'] = p2c

        kek = self.get_aes_key(public_key.get_op_key('wrapKey'), p2s, p2c)
        aeskw: AESAlgModel = AES_KW_MAP[self.key_size]
        return aeskw.wrap(enc, obj, recipient, kek)

    def unwrap(self, enc: JWEEncModel, obj: EncryptionData, recipient: Recipient,
               private_key: OctKey) -> bytes:
        p2s = getattr(obj, '_p2s', None)
        if not p2s:
            p2s = urlsafe_b64decode(to_bytes(obj.protected['p2s']))
            setattr(obj, '_p2s', p2s)
        p2c = obj.protected['p2c']
        kek = self.get_aes_key(private_key.get_op_key('unwrapKey'), p2s, p2c)
        aeskw = AES_KW_MAP[self.key_size]
        return aeskw.unwrap(enc, obj, recipient, kek)


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
