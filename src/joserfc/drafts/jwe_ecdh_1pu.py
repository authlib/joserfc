import typing as t
from ..rfc7516.models import Recipient, JWEAlgModel, JWEEncModel
from ..rfc7517.models import CurveKey
from ..rfc7518.oct_key import OctKey
from ..rfc7518.jwe_algs import (
    compute_concat_kdf_info,
    compute_derived_key_for_concat_kdf,
    A128KW,
    A192KW,
    A256KW,
)
from ..rfc7518.jwe_encs import CBCHS2EncModel
from ..registry import Header, HeaderParameter, is_jwk, is_str
from ..errors import InvalidEncryptionAlgorithmError
from ..util import u32be_len_input


class ECDH1PUAlgModel(JWEAlgModel):
    """ Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model (ECDH-1PU)

    https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04
    """

    more_header_registry = {
        "epk": HeaderParameter("Ephemeral Public Key", True, is_jwk),
        "apu": HeaderParameter("Agreement PartyUInfo", False, is_str),
        "apv": HeaderParameter("Agreement PartyVInfo", False, is_str),
        "skid": HeaderParameter("Sender Key ID", False, is_str),
    }
    key_agreement: bool = True

    def __init__(self, key_wrapping: t.Optional[JWEAlgModel]=None):
        if key_wrapping is None:
            self.name = "ECDH-1PU"
            self.description = "ECDH-1PU using one-pass KDF and CEK in the Direct Key Agreement mode"
            self.key_size = None
        else:
            self.name = f"ECDH-1PU+{key_wrapping.name}"
            self.description = f"ECDH-1PU using one-pass KDF and CEK wrapped with {key_wrapping.name}"
            self.key_size = key_wrapping.key_size
        self.key_wrapping = key_wrapping

    def _check_enc(self, enc: JWEEncModel):
        if self.key_wrapping and not isinstance(enc, CBCHS2EncModel):
            description = (
                'In key agreement with key wrapping mode ECDH-1PU algorithm '
                'only supports AES_CBC_HMAC_SHA2 family encryption algorithms'
            )
            raise InvalidEncryptionAlgorithmError(description)

    def get_bit_size(self, enc: JWEEncModel) -> int:
        if self.key_size is None:
            bit_size = enc.cek_size
        else:
            bit_size = self.key_size
        return bit_size

    def compute_derived_key(self, shared_key: bytes, header: Header, bit_size: int, tag: t.Optional[bytes]=None):
        fixed_info = compute_concat_kdf_info(self.key_size, header, bit_size)
        if tag:
            cctag = u32be_len_input(tag)
            fixed_info += cctag
        return compute_derived_key_for_concat_kdf(shared_key, bit_size, fixed_info)

    def encrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, sender_key: CurveKey) -> bytes:
        self._check_enc(enc)

        if recipient.ephemeral_key is None:
            recipient.ephemeral_key = sender_key.generate_key(sender_key.curve_name, private=True)

        recipient_key: CurveKey = recipient.recipient_key
        recipient_pubkey = recipient_key.get_op_key("deriveKey")
        sender_shared_key = sender_key.exchange_shared_key(recipient_pubkey)
        ephemeral_shared_key = recipient.ephemeral_key.exchange_shared_key(recipient_pubkey)
        shared_key = ephemeral_shared_key + sender_shared_key

        bit_size = self.get_bit_size(enc)
        dk = self.compute_derived_key(shared_key, recipient.headers(), bit_size)
        recipient.add_header("epk", recipient.ephemeral_key.as_dict(private=False))

        if self.key_wrapping:
            return self.key_wrapping.encrypt_recipient(enc, recipient, OctKey.import_key(dk))

        obj = recipient.parent
        assert obj.cek is None
        obj.cek = dk
        return b""

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, sender_key: CurveKey) -> bytes:
        self._check_enc(enc)

        headers = recipient.headers()
        assert "epk" in headers

        recipient_key: CurveKey = recipient.recipient_key
        ephemeral_key = recipient_key.import_key(headers["epk"])
        ephemeral_pubkey = ephemeral_key.get_op_key("deriveKey")
        sender_pubkey = sender_key.get_op_key("deriveKey")
        sender_shared_key = recipient_key.exchange_shared_key(sender_pubkey)
        ephemeral_shared_key = recipient_key.exchange_shared_key(ephemeral_pubkey)
        shared_key = ephemeral_shared_key + sender_shared_key

        bit_size = self.get_bit_size(enc)
        dk = self.compute_derived_key(shared_key, headers, bit_size)

        if self.key_wrapping:
            return self.key_wrapping.decrypt_recipient(enc, recipient, OctKey.import_key(dk))
        return dk


JWE_ALG_MODELS = [
    ECDH1PUAlgModel(None),    # ECDH-1PU
    ECDH1PUAlgModel(A128KW),  # ECDH-1PU+A128KW
    ECDH1PUAlgModel(A192KW),  # ECDH-1PU+A192KW
    ECDH1PUAlgModel(A256KW),  # ECDH-1PU+A256KW
]
