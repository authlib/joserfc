from cryptography.exceptions import InvalidSignature
from ..rfc7515.model import JWSAlgModel
from .okp_key import OKPKey


class EdDSAAlgModel(JWSAlgModel):
    name = 'EdDSA'
    description = 'Edwards-curve Digital Signature Algorithm for JWS'

    def sign(self, msg: bytes, key: OKPKey) -> bytes:
        op_key = key.get_op_key('sign')
        return op_key.sign(msg)

    def verify(self, msg: bytes, sig: bytes, key: OKPKey) -> bool:
        op_key = key.get_op_key('verify')
        try:
            op_key.verify(sig, msg)
            return True
        except InvalidSignature:
            return False

EdDSA = EdDSAAlgModel()
