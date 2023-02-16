from cryptography.hazmat.primitives.asymmetric.ec import SECP256K1
from ..rfc7518.ec_key import DSS_CURVES, CURVES_DSS
from ..rfc7518.jws_algs import ECAlgModel

# patch ECKey
# https://tools.ietf.org/html/rfc8812#section-3.1
DSS_CURVES['secp256k1'] = SECP256K1
CURVES_DSS[SECP256K1.name] = 'secp256k1'

ES256K = ECAlgModel('ES256K', 'secp256k1', 256)

__all__ = ['ES256K']
