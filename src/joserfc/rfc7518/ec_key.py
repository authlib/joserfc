from typing import Optional, Union, Dict
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1
)
from cryptography.hazmat.backends import default_backend
from ..rfc7517 import CurveKey
from ..rfc7517.pem import CryptographyBinding
from ..rfc7517.types import KeyDict, KeyAny, KeyOptions
from ..util import base64_to_int, int_to_base64


NativeECKey = Union[EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization]
DSS_CURVES = {
    'P-256': SECP256R1,
    'P-384': SECP384R1,
    'P-521': SECP521R1,
}
CURVES_DSS = {
    SECP256R1.name: 'P-256',
    SECP384R1.name: 'P-384',
    SECP521R1.name: 'P-521',
}


class ECKey(CurveKey):
    """Key class of the ``EC`` key type."""

    key_type: str = 'EC'
    required_fields = frozenset(['crv', 'x', 'y'])
    private_only_fields = frozenset(['d'])

    def exchange_shared_key(self, pubkey):
        # used in ECDHESAlgorithm
        if self.private_key:
            return self.private_key.exchange(ec.ECDH(), pubkey)
        raise ValueError('Invalid key for exchanging shared key')

    @property
    def raw_key(self) -> NativeECKey:
        return self.value

    def get_op_key(self, operation: str) -> NativeECKey:
        self.check_key_op(operation)
        if operation in self.private_key_ops:
            return self.private_key
        return self.public_key

    def as_dict(self, private: Optional[bool]=None, **params) -> KeyDict:
        if private is True and not self.is_private:
            raise ValueError("This is a public EC key")
        return ECBinding.as_dict(self, private, **params)

    def as_bytes(
            self,
            encoding: Optional[str]=None,
            private: Optional[bool]=None,
            password: Optional[str]=None) -> bytes:
        return ECBinding.as_bytes(self, encoding, private, password)

    @property
    def is_private(self) -> bool:
        return isinstance(self.value, EllipticCurvePrivateKeyWithSerialization)

    @cached_property
    def public_key(self) -> EllipticCurvePublicKey:
        if isinstance(self.value, EllipticCurvePrivateKeyWithSerialization):
            return self.value.public_key()
        return self.value

    @property
    def private_key(self) -> Optional[EllipticCurvePrivateKeyWithSerialization]:
        if self.is_private:
            return self.value
        return None

    @property
    def curve_name(self) -> str:
        return CURVES_DSS[self.raw_key.curve.name]

    @property
    def curve_key_size(self) -> int:
        return self.raw_key.curve.key_size

    @classmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None) -> 'ECKey':
        return ECBinding.import_key(cls, value, options)

    @classmethod
    def generate_key(cls, crv: str='P-256',
                     options: KeyOptions=None,
                     private: bool=False) -> 'ECKey':
        if crv not in DSS_CURVES:
            raise ValueError('Invalid crv value: "{}"'.format(crv))
        raw_key = ec.generate_private_key(
            curve=DSS_CURVES[crv](),
            backend=default_backend(),
        )
        if not private:
            raw_key = raw_key.public_key()
        return cls(raw_key, options)


class ECBinding(CryptographyBinding):
    ssh_type = b'ecdsa-sha2-'

    @staticmethod
    def import_private_key(obj: KeyDict) -> EllipticCurvePrivateKeyWithSerialization:
        curve = DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        private_numbers = EllipticCurvePrivateNumbers(
            base64_to_int(obj['d']),
            public_numbers
        )
        return private_numbers.private_key(default_backend())

    @staticmethod
    def export_private_key(key: EllipticCurvePrivateKeyWithSerialization) -> Dict[str, str]:
        numbers = key.private_numbers()
        return {
            'crv': CURVES_DSS[key.curve.name],
            'x': int_to_base64(numbers.public_numbers.x),
            'y': int_to_base64(numbers.public_numbers.y),
            'd': int_to_base64(numbers.private_value),
        }

    @staticmethod
    def import_public_key(obj: KeyDict) -> EllipticCurvePublicKey:
        curve = DSS_CURVES[obj['crv']]()
        public_numbers = EllipticCurvePublicNumbers(
            base64_to_int(obj['x']),
            base64_to_int(obj['y']),
            curve,
        )
        return public_numbers.public_key(default_backend())

    @staticmethod
    def export_public_key(key: EllipticCurvePublicKey) -> Dict[str, str]:
        numbers = key.public_numbers()
        return {
            'crv': CURVES_DSS[numbers.curve.name],
            'x': int_to_base64(numbers.x),
            'y': int_to_base64(numbers.y)
        }
