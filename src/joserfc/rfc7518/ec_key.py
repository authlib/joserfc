from typing import Optional, Union, Dict, FrozenSet
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey, EllipticCurvePrivateKeyWithSerialization,
    EllipticCurvePrivateNumbers, EllipticCurvePublicNumbers,
    SECP256R1, SECP384R1, SECP521R1
)
from cryptography.hazmat.backends import default_backend
from ..rfc7517.keys import CurveKey, DictKey, RawKey, KeyOptions
from ..rfc7517.pem import load_pem_key
from .._util import base64_to_int, int_to_base64


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
    required_fields: FrozenSet[str] = frozenset(['crv', 'x', 'y'])
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

    def as_dict(self, private: Optional[bool]=None, **params) -> DictKey:
        if private is True and not self.is_private:
            raise ValueError("This is a public EC key")

        if self._tokens:
            data = self._tokens.copy()
            # clear private fields
            if private is False and self.is_private:
                for k in self.private_only_fields:
                    if k in data:
                        del data[k]

        elif private is True:
            data = export_private_key(self.private_key)
        elif private is False:
            data = export_public_key(self.public_key)
        elif self.is_private:
            data = export_private_key(self.private_key)
        else:
            data = export_public_key(self.public_key)

        data.update(params)
        return data

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
    def import_key(cls, value: RawKey, options: KeyOptions=None) -> 'ECKey':
        if isinstance(value, dict):
            tokens = cls.validate_tokens(value)
            if 'd' in value:
                raw_key = import_private_key(value)
            else:
                raw_key = import_public_key(value)
            return cls(raw_key, options, tokens)

        if isinstance(value, str):
            value = to_bytes(value)

        raw_key = load_pem_key(value, b'ecdsa-sha2-')
        return cls(raw_key, options)

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


def import_private_key(obj: DictKey) -> EllipticCurvePrivateKeyWithSerialization:
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


def export_private_key(key: EllipticCurvePrivateKeyWithSerialization) -> Dict[str, str]:
    numbers = key.private_numbers()
    return {
        'crv': CURVES_DSS[key.curve.name],
        'x': int_to_base64(numbers.public_numbers.x),
        'y': int_to_base64(numbers.public_numbers.y),
        'd': int_to_base64(numbers.private_value),
    }


def import_public_key(obj: DictKey) -> EllipticCurvePublicKey:
    curve = DSS_CURVES[obj['crv']]()
    public_numbers = EllipticCurvePublicNumbers(
        base64_to_int(obj['x']),
        base64_to_int(obj['y']),
        curve,
    )
    return public_numbers.public_key(default_backend())


def export_public_key(key: EllipticCurvePublicKey) -> Dict[str, str]:
    numbers = key.public_numbers()
    return {
        'crv': CURVES_DSS[numbers.curve.name],
        'x': int_to_base64(numbers.x),
        'y': int_to_base64(numbers.y)
    }
