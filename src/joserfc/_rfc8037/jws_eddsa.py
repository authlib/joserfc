from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey, Ed448PrivateKey
from .._rfc7515.model import JWSAlgModel
from .okp_key import OKPKey


class EdDSAAlgorithm(JWSAlgModel):
    name = "EdDSA"
    description = "Edwards-curve Digital Signature Algorithm for JWS"
    key_type = "OKP"

    def sign(self, msg: bytes, key: OKPKey) -> bytes:
        op_key = key.get_op_key("sign")
        assert isinstance(op_key, (Ed25519PrivateKey, Ed448PrivateKey))
        return op_key.sign(msg)

    def verify(self, msg: bytes, sig: bytes, key: OKPKey) -> bool:
        op_key = key.get_op_key("verify")
        assert isinstance(op_key, (Ed25519PublicKey, Ed448PublicKey))
        try:
            op_key.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


EdDSA = EdDSAAlgorithm()

# compatible
EdDSAAlgModel = EdDSAAlgorithm
