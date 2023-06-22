from typing import Optional, Dict
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key,
    ECDH,
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.backends import default_backend
from ..rfc7517.models import CurveKey
from ..rfc7517.pem import CryptographyBinding
from ..rfc7517.types import KeyDict, KeyOptions
from ..util import base64_to_int, int_to_base64
from ..registry import KeyParameter


DSS_CURVES = {
    "P-256": SECP256R1,
    "P-384": SECP384R1,
    "P-521": SECP521R1,
}
CURVES_DSS = {
    SECP256R1.name: "P-256",
    SECP384R1.name: "P-384",
    SECP521R1.name: "P-521",
}


class ECBinding(CryptographyBinding):
    ssh_type = b"ecdsa-sha2-"

    @staticmethod
    def import_private_key(obj: KeyDict) -> EllipticCurvePrivateKey:
        curve = DSS_CURVES[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        private_numbers = EllipticCurvePrivateNumbers(base64_to_int(obj["d"]), public_numbers)
        return private_numbers.private_key(default_backend())

    @staticmethod
    def export_private_key(key: EllipticCurvePrivateKey) -> Dict[str, str]:
        numbers = key.private_numbers()
        return {
            "crv": CURVES_DSS[key.curve.name],
            "x": int_to_base64(numbers.public_numbers.x),
            "y": int_to_base64(numbers.public_numbers.y),
            "d": int_to_base64(numbers.private_value),
        }

    @staticmethod
    def import_public_key(obj: KeyDict) -> EllipticCurvePublicKey:
        curve = DSS_CURVES[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @staticmethod
    def export_public_key(key: EllipticCurvePublicKey) -> Dict[str, str]:
        numbers = key.public_numbers()
        return {
            "crv": CURVES_DSS[numbers.curve.name],
            "x": int_to_base64(numbers.x),
            "y": int_to_base64(numbers.y),
        }


class ECKey(CurveKey[EllipticCurvePublicKey, EllipticCurvePrivateKey]):
    key_type: str = "EC"
    #: Registry definition for EC Key
    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.2
    value_registry = {
        "crv": KeyParameter("Curve", "str", private=False, required=True),
        "x": KeyParameter("X Coordinate", "str", private=False, required=True),
        "y": KeyParameter("Y Coordinate", "str", private=False, required=True),
        "d": KeyParameter("EC Private Key", "str", private=True, required=False),
    }
    binding = ECBinding

    def exchange_shared_key(self, pubkey: EllipticCurvePublicKey) -> bytes:
        # used in ECDHESAlgorithm
        if self.private_key:
            return self.private_key.exchange(ECDH(), pubkey)
        raise ValueError("Invalid key for exchanging shared key")

    @property
    def is_private(self) -> bool:
        return isinstance(self.raw_value, EllipticCurvePrivateKey)

    @cached_property
    def public_key(self) -> EllipticCurvePublicKey:
        if isinstance(self.raw_value, EllipticCurvePrivateKey):
            return self.raw_value.public_key()
        return self.raw_value

    @property
    def private_key(self) -> Optional[EllipticCurvePrivateKey]:
        if self.is_private:
            return self.raw_value
        return None

    @property
    def curve_name(self) -> str:
        return CURVES_DSS[self.raw_value.curve.name]

    @property
    def curve_key_size(self) -> int:
        return self.raw_value.curve.key_size

    @classmethod
    def generate_key(
            cls,
            crv: str = "P-256",
            options: KeyOptions = None,
            private: bool = True) -> "ECKey":
        if crv not in DSS_CURVES:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        raw_key = generate_private_key(
            curve=DSS_CURVES[crv](),
            backend=default_backend(),
        )
        if not private:
            raw_key = raw_key.public_key()
        return cls(raw_key, raw_key, options)
