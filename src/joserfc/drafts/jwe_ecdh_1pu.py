import typing as t
from ..rfc7516.models import JWEAlgModel, JWEEncModel
from ..rfc7516.types import EncryptionData, Recipient, Header
from ..rfc7517.models import CurveKey
from ..rfc7518.jwe_algs import (
    compute_concat_kdf_info,
    compute_derived_key_for_concat_kdf,
)
from ..registry import HeaderParameter, is_jwk, is_str
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
            self.key_wrapping = key_wrapping
            self.key_size = key_wrapping.key_size

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
        if recipient.ephemeral_key is None:
            # TODO: assign sender key
            recipient.ephemeral_key = sender_key.generate_key(sender_key.curve_name, private=True)

    def decrypt_recipient(self, enc: JWEEncModel, recipient: Recipient, sender_key: CurveKey) -> bytes:
        headers = recipient.headers()
        assert "epk" in headers
        epk = sender_key.import_key(headers["epk"])


JWE_ALG_MODELS = [
]
