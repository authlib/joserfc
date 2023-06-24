import typing as t
from ..rfc7516.models import (
    Recipient,
    JWEKeyAgreement,
    JWEKeyWrapping,
    JWEEncModel
)
from ..rfc7517.models import CurveKey
from ..rfc7518.jwe_algs import (
    A128KW,
    A192KW,
    A256KW,
)
from ..rfc7518.derive_key import (
    derive_key_for_concat_kdf,
)
from ..rfc7518.jwe_encs import CBCHS2EncModel
from ..registry import HeaderParameter
from ..errors import InvalidEncryptionAlgorithmError


class ECDH1PUAlgModel(JWEKeyAgreement):
    """ Key Agreement with Elliptic Curve Diffie-Hellman One-Pass Unified Model (ECDH-1PU)

    https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04
    """
    more_header_registry = {
        "epk": HeaderParameter("Ephemeral Public Key", "jwk", True),
        "apu": HeaderParameter("Agreement PartyUInfo", "str"),
        "apv": HeaderParameter("Agreement PartyVInfo", "str"),
        "skid": HeaderParameter("Sender Key ID", "str"),
    }
    tag_aware = True
    recommended: bool = False

    def __init__(self, key_wrapping: t.Optional[JWEKeyWrapping]=None):
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

    def encrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient) -> bytes:
        self._check_enc(enc)
        return self.__encrypt_agreed_upon_key(enc, recipient, None)

    def encrypt_agreed_upon_key_with_tag(self, enc: JWEEncModel, recipient: Recipient, tag: bytes) -> bytes:
        self._check_enc(enc)
        return self.__encrypt_agreed_upon_key(enc, recipient, tag)

    def decrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient) -> bytes:
        return self.__decrypt_agreed_upon_key(enc, recipient, None)

    def decrypt_agreed_upon_key_with_tag(self, enc: JWEEncModel, recipient: Recipient, tag: bytes) -> bytes:
        return self.__decrypt_agreed_upon_key(enc, recipient, tag)

    def __encrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient, tag: t.Optional[bytes]) -> bytes:
        sender_key: CurveKey = recipient.sender_key
        recipient_pubkey = recipient.recipient_key.get_op_key("deriveKey")
        sender_shared_key = sender_key.exchange_shared_key(recipient_pubkey)
        ephemeral_shared_key = recipient.ephemeral_key.exchange_shared_key(recipient_pubkey)
        shared_key = ephemeral_shared_key + sender_shared_key
        header = recipient.headers()
        return derive_key_for_concat_kdf(shared_key, header, enc.cek_size, self.key_size, tag)

    def __decrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient, tag: t.Optional[bytes]) -> bytes:
        self._check_enc(enc)

        header = recipient.headers()
        assert "epk" in header

        recipient_key: CurveKey = recipient.recipient_key
        sender_key: CurveKey = recipient.sender_key

        ephemeral_key = recipient_key.import_key(header["epk"])
        ephemeral_pubkey = ephemeral_key.get_op_key("deriveKey")
        sender_pubkey = sender_key.get_op_key("deriveKey")

        sender_shared_key = recipient_key.exchange_shared_key(sender_pubkey)
        ephemeral_shared_key = recipient_key.exchange_shared_key(ephemeral_pubkey)
        shared_key = ephemeral_shared_key + sender_shared_key
        return derive_key_for_concat_kdf(shared_key, header, enc.cek_size, self.key_size, tag)


JWE_ALG_MODELS = [
    ECDH1PUAlgModel(None),    # ECDH-1PU
    ECDH1PUAlgModel(A128KW),  # ECDH-1PU+A128KW
    ECDH1PUAlgModel(A192KW),  # ECDH-1PU+A192KW
    ECDH1PUAlgModel(A256KW),  # ECDH-1PU+A256KW
]
