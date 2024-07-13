from __future__ import annotations
import typing as t
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key,
    ECDH,
    EllipticCurvePublicKey,
    EllipticCurvePrivateKey,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    EllipticCurve,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.backends import default_backend
from ..errors import InvalidExchangeKeyError
from ..rfc7517.models import CurveKey
from ..rfc7517.pem import CryptographyBinding
from ..rfc7517.types import KeyParameters
from ..util import base64_to_int, int_to_base64
from ..registry import KeyParameter

ECDictKey = t.TypedDict("ECDictKey", {
    "crv": str,
    "x": str,
    "y": str,
    "d": str,  # optional
}, total=False)

DSS_CURVES: t.Dict[str, t.Type[EllipticCurve]] = {
    "P-256": SECP256R1,
    "P-384": SECP384R1,
    "P-521": SECP521R1,
}
CURVES_DSS: t.Dict[str, str] = {
    SECP256R1.name: "P-256",
    SECP384R1.name: "P-384",
    SECP521R1.name: "P-521",
}


class ECBinding(CryptographyBinding):
    ssh_type = b"ecdsa-sha2-"

    @staticmethod
    def import_private_key(obj: ECDictKey) -> EllipticCurvePrivateKey:
        curve = DSS_CURVES[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        d = base64_to_int(obj["d"])
        private_numbers = EllipticCurvePrivateNumbers(d, public_numbers)
        return private_numbers.private_key(default_backend())

    @staticmethod
    def export_private_key(key: EllipticCurvePrivateKey) -> ECDictKey:
        numbers = key.private_numbers()
        return {
            "crv": CURVES_DSS[key.curve.name],
            "x": int_to_base64(numbers.public_numbers.x),
            "y": int_to_base64(numbers.public_numbers.y),
            "d": int_to_base64(numbers.private_value),
        }

    @staticmethod
    def import_public_key(obj: ECDictKey) -> EllipticCurvePublicKey:
        curve = DSS_CURVES[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @staticmethod
    def export_public_key(key: EllipticCurvePublicKey) -> ECDictKey:
        numbers = key.public_numbers()
        return {
            "crv": CURVES_DSS[numbers.curve.name],
            "x": int_to_base64(numbers.x),
            "y": int_to_base64(numbers.y),
        }


class ECKey(CurveKey[EllipticCurvePrivateKey, EllipticCurvePublicKey]):
    key_type = "EC"
    #: Registry definition for EC Key
    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.2
    value_registry = {
        "crv": KeyParameter("Curve", "str", private=False, required=True),
        "x": KeyParameter("X Coordinate", "str", private=False, required=True),
        "y": KeyParameter("Y Coordinate", "str", private=False, required=True),
        "d": KeyParameter("EC Private Key", "str", private=True, required=False),
    }
    binding = ECBinding

    @property
    def is_private(self) -> bool:
        return isinstance(self.raw_value, EllipticCurvePrivateKey)

    @cached_property
    def public_key(self) -> EllipticCurvePublicKey:
        if isinstance(self.raw_value, EllipticCurvePrivateKey):
            return self.raw_value.public_key()
        return self.raw_value

    @property
    def private_key(self) -> EllipticCurvePrivateKey | None:
        if isinstance(self.raw_value, EllipticCurvePrivateKey):
            return self.raw_value
        return None

    def exchange_derive_key(self, key: "ECKey") -> bytes:
        pubkey = key.get_op_key("deriveKey")
        if self.private_key and self.curve_name == key.curve_name:
            return self.private_key.exchange(ECDH(), pubkey)
        raise InvalidExchangeKeyError()

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
            parameters: KeyParameters | None = None,
            private: bool = True,
            auto_kid: bool = False) -> "ECKey":
        """Generate a ``ECKey`` with the given "crv" value.

        :param crv: ECKey curve name
        :param parameters: extra parameter in JWK
        :param private: generate a private key or public key
        :param auto_kid: add ``kid`` automatically
        """
        if crv not in DSS_CURVES:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        raw_key = generate_private_key(
            curve=DSS_CURVES[crv](),
            backend=default_backend(),
        )
        if private:
            key = cls(raw_key, raw_key, parameters)
        else:
            pub_key = raw_key.public_key()
            key = cls(pub_key, pub_key, parameters)
        if auto_kid:
            key.ensure_kid()
        return key
