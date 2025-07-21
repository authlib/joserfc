from ._rfc7518.jws_algs import (
    NoneAlgorithm,
    HMACAlgorithm,
    RSAAlgorithm,
    ECAlgorithm,
    RSAPSSAlgorithm,
    JWS_ALGORITHMS as _JWS_ALGORITHMS,
)
from ._rfc7518.jwe_algs import (
    DirectAlgEncryption,
    AESAlgKeyWrapping,
    ECDHESAlgKeyAgreement,
    AESGCMAlgKeyWrapping,
    PBES2HSAlgKeyEncryption,
    JWE_ALG_MODELS,
)
from ._rfc7518.jwe_encs import (
    CBCHS2EncModel,
    GCMEncModel,
    JWE_ENC_MODELS,
)
from ._rfc7518.jwe_zips import (
    DeflateZipModel,
    JWE_ZIP_MODELS,
)
from ._rfc8037.jws_eddsa import EdDSA, EdDSAAlgorithm
from ._rfc8812 import ES256K

__all__ = [
    # JWS algorithms
    "JWS_ALGORITHMS",
    "NoneAlgorithm",
    "HMACAlgorithm",
    "RSAAlgorithm",
    "ECAlgorithm",
    "RSAPSSAlgorithm",
    "EdDSAAlgorithm",
    # JWE algorithms
    "JWE_ALG_MODELS",
    "JWE_ENC_MODELS",
    "JWE_ZIP_MODELS",
    "DirectAlgEncryption",
    "AESAlgKeyWrapping",
    "ECDHESAlgKeyAgreement",
    "AESGCMAlgKeyWrapping",
    "PBES2HSAlgKeyEncryption",
    "CBCHS2EncModel",
    "GCMEncModel",
    "DeflateZipModel",
]

JWS_ALGORITHMS = [
    *_JWS_ALGORITHMS,
    EdDSA,
    ES256K,
]
