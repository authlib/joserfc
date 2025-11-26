import typing as t
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey, Ed448PrivateKey
from ..errors import InvalidKeyTypeError
from .._rfc7515.model import JWSAlgModel
from .._rfc8037.okp_key import OKPKey


_private_key_mapping = {"Ed25519": Ed25519PrivateKey, "Ed448": Ed448PrivateKey}
_public_key_mapping = {"Ed25519": Ed25519PublicKey, "Ed448": Ed448PublicKey}


class EdDSAAlgorithm(JWSAlgModel):
    key_type = "OKP"

    def __init__(self, curve: t.Literal["Ed25519", "Ed448"]):
        self.name = curve
        self.description = f"EdDSA using the {curve} parameter set"

    def sign(self, msg: bytes, key: OKPKey) -> bytes:
        op_key = t.cast(t.Union[Ed25519PrivateKey, Ed448PrivateKey], key.get_op_key("sign"))
        private_key_cls = _private_key_mapping[self.name]
        if not isinstance(op_key, private_key_cls):
            raise InvalidKeyTypeError(f"Algorithm '{self.name}' requires '{self.name}' OKP key")
        return op_key.sign(msg)

    def verify(self, msg: bytes, sig: bytes, key: OKPKey) -> bool:
        op_key = t.cast(t.Union[Ed25519PublicKey, Ed448PublicKey], key.get_op_key("verify"))
        public_key_cls = _public_key_mapping[self.name]
        if not isinstance(op_key, public_key_cls):
            raise InvalidKeyTypeError(f"Algorithm '{self.name}' requires '{self.name}' OKP key")
        try:
            op_key.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


Ed25519 = EdDSAAlgorithm("Ed25519")
Ed448 = EdDSAAlgorithm("Ed448")

JWS_ALGORITHMS: list[EdDSAAlgorithm] = [Ed25519, Ed448]
