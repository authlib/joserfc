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
from .._rfc7517.models import CurveKey
from .._rfc7517.pem import CryptographyBinding
from .._rfc7517.types import KeyParameters, AnyKey
from ..util import base64_to_int, int_to_base64
from ..registry import KeyParameter

__all__ = ["ECKey"]

ECDictKey = t.TypedDict(
    "ECDictKey",
    {
        "crv": str,
        "x": str,
        "y": str,
        "d": str,  # optional
    },
    total=False,
)


class ECBinding(CryptographyBinding):
    ssh_type = b"ecdsa-sha2-"

    _dss_curves: dict[str, t.Type[EllipticCurve]] = {}
    _curves_dss: dict[str, str] = {}

    @classmethod
    def register_curve(cls, name: str, curve: t.Type[EllipticCurve]) -> None:
        cls._dss_curves[name] = curve
        cls._curves_dss[str(curve.name)] = name

    @classmethod
    def generate_private_key(cls, name: str) -> EllipticCurvePrivateKey:
        if name not in cls._dss_curves:
            raise ValueError("Invalid crv value: '{}'".format(name))

        curve = cls._dss_curves[name]()
        raw_key = generate_private_key(
            curve=curve,
            backend=default_backend(),
        )
        return raw_key

    @classmethod
    def import_private_key(cls, obj: ECDictKey) -> EllipticCurvePrivateKey:
        curve = cls._dss_curves[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        d = base64_to_int(obj["d"])
        private_numbers = EllipticCurvePrivateNumbers(d, public_numbers)
        return private_numbers.private_key(default_backend())

    @classmethod
    def export_private_key(cls, key: EllipticCurvePrivateKey) -> ECDictKey:
        numbers = key.private_numbers()
        return {
            "crv": cls._curves_dss[key.curve.name],
            "x": int_to_base64(numbers.public_numbers.x),
            "y": int_to_base64(numbers.public_numbers.y),
            "d": int_to_base64(numbers.private_value),
        }

    @classmethod
    def import_public_key(cls, obj: ECDictKey) -> EllipticCurvePublicKey:
        curve = cls._dss_curves[obj["crv"]]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj["x"]),
            base64_to_int(obj["y"]),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @classmethod
    def export_public_key(cls, key: EllipticCurvePublicKey) -> ECDictKey:
        numbers = key.public_numbers()
        return {
            "crv": cls._curves_dss[numbers.curve.name],
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
        return self.binding._curves_dss[self.raw_value.curve.name]

    @property
    def curve_key_size(self) -> int:
        return self.raw_value.curve.key_size

    @classmethod
    def import_key(
        cls: t.Any,
        value: AnyKey,
        parameters: KeyParameters | None = None,
        password: t.Any = None,
    ) -> "ECKey":
        return super(ECKey, cls).import_key(value, parameters, password)

    @classmethod
    def generate_key(
        cls,
        crv: str | None = "P-256",
        parameters: KeyParameters | None = None,
        private: bool = True,
        auto_kid: bool = False,
    ) -> "ECKey":
        """Generate a ``ECKey`` with the given "crv" value.

        :param crv: ECKey curve name
        :param parameters: extra parameter in JWK
        :param private: generate a private key or public key
        :param auto_kid: add ``kid`` automatically
        """
        if crv is None:
            crv = "P-256"

        raw_key = cls.binding.generate_private_key(crv)
        if private:
            key = cls(raw_key, raw_key, parameters)
        else:
            pub_key = raw_key.public_key()
            key = cls(pub_key, pub_key, parameters)
        if auto_kid:
            key.ensure_kid()
        return key


# register default curves with their DSS (Digital Signature Standard) names
# https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
ECBinding.register_curve("P-256", SECP256R1)
ECBinding.register_curve("P-384", SECP384R1)
ECBinding.register_curve("P-521", SECP521R1)
