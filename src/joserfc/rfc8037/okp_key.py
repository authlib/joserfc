from typing import Optional, Union, Dict, FrozenSet
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey, Ed25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PublicKey, Ed448PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PublicKey, X25519PrivateKey
)
from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PublicKey, X448PrivateKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from ..rfc7517.keys import CurveKey
from ..rfc7517.types import KeyDict, KeyAny, KeyOptions
from ..rfc7517.pem import load_pem_key
from ..util import to_bytes, urlsafe_b64decode, urlsafe_b64encode


PUBLIC_KEYS_MAP = {
    'Ed25519': Ed25519PublicKey,
    'Ed448': Ed448PublicKey,
    'X25519': X25519PublicKey,
    'X448': X448PublicKey,
}
PRIVATE_KEYS_MAP = {
    'Ed25519': Ed25519PrivateKey,
    'Ed448': Ed448PrivateKey,
    'X25519': X25519PrivateKey,
    'X448': X448PrivateKey,
}

PublicOKPKey = Union[
    Ed25519PublicKey,
    Ed448PublicKey,
    X25519PublicKey,
    X448PublicKey
]

PrivateOKPKey = Union[
    Ed25519PrivateKey,
    Ed448PrivateKey,
    X25519PrivateKey,
    X448PrivateKey,
]

NativeOKPKey = Union[PublicOKPKey, PrivateOKPKey]

ExchangeKeys = (X25519PrivateKey, X448PrivateKey)



class OKPKey(CurveKey):
    """Key class of the ``OKP`` key type."""

    key_type: str = 'OKP'
    required_fields: FrozenSet[str] = frozenset(['crv', 'x'])
    private_only_fields = frozenset(['d'])

    def exchange_shared_key(self, pubkey):
        # used in ECDHESAlgorithm
        if self.private_key and isinstance(self.private_key, ExchangeKeys):
            return self.private_key.exchange(pubkey)
        raise ValueError('Invalid key for exchanging shared key')

    @property
    def raw_key(self) -> NativeOKPKey:
        return self.value

    def get_op_key(self, operation: str) -> NativeOKPKey:
        self.check_key_op(operation)
        if operation in self.private_key_ops:
            return self.private_key
        return self.public_key

    def as_dict(self, private: Optional[bool]=None, **params) -> KeyDict:
        if private is True and not self.is_private:
            raise ValueError("This is a public OKP key")

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
        return isinstance(self.value, PrivateOKPKey)

    @cached_property
    def public_key(self) -> PublicOKPKey:
        if isinstance(self.value, EllipticCurvePrivateKeyWithSerialization):
            return self.value.public_key()
        return self.value

    @property
    def private_key(self) -> Optional[PrivateOKPKey]:
        if self.is_private:
            return self.value
        return None

    @property
    def curve_name(self) -> str:
        return get_key_curve(self.value)

    @classmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None) -> 'OKPKey':
        if isinstance(value, dict):
            tokens = cls.validate_tokens(value)
            if 'd' in value:
                raw_key = import_private_key(value)
            else:
                raw_key = import_public_key(value)
            key = cls(raw_key, options)
            key._tokens = key.render_tokens(tokens)
            return key

        if isinstance(value, str):
            value = to_bytes(value)

        raw_key = load_pem_key(value, b'ssh-ed25519')
        return cls(raw_key, options)

    @classmethod
    def generate_key(cls, crv: str='Ed25519',
                     options: KeyOptions=None,
                     private: bool=False) -> 'OKPKey':
        if crv not in PRIVATE_KEYS_MAP:
            raise ValueError('Invalid crv value: "{}"'.format(crv))

        private_key_cls = PRIVATE_KEYS_MAP[crv]
        raw_key = private_key_cls.generate()
        if not private:
            raw_key = raw_key.public_key()
        return cls(raw_key, options=options)


def get_key_curve(key: NativeOKPKey):
    if isinstance(key, (Ed25519PublicKey, Ed25519PrivateKey)):
        return 'Ed25519'
    elif isinstance(key, (Ed448PublicKey, Ed448PrivateKey)):
        return 'Ed448'
    elif isinstance(key, (X25519PublicKey, X25519PrivateKey)):
        return 'X25519'
    elif isinstance(key, (X448PublicKey, X448PrivateKey)):
        return 'X448'
    raise ValueError("Invalid key")


def import_private_key(obj: KeyDict) -> PrivateOKPKey:
    crv_key = PRIVATE_KEYS_MAP[obj['crv']]
    d_bytes = urlsafe_b64decode(to_bytes(obj['d']))
    return crv_key.from_private_bytes(d_bytes)


def import_public_key(obj: KeyDict) -> PublicOKPKey:
    crv_key = PUBLIC_KEYS_MAP[obj['crv']]
    x_bytes = urlsafe_b64decode(to_bytes(obj['x']))
    return crv_key.from_public_bytes(x_bytes)


def export_private_key(key: PrivateOKPKey) -> Dict[str, str]:
    obj = export_public_key(key.public_key())
    d_bytes = key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption()
    )
    obj['d'] = urlsafe_b64encode(d_bytes).decode('utf-8')
    return obj


def export_public_key(key: PublicOKPKey) -> Dict[str, str]:
    x_bytes = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        'crv': get_key_curve(key),
        'x': to_unicode(urlsafe_b64encode(x_bytes)),
    }
