from typing import Optional, Union, Dict, FrozenSet
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKeyWithSerialization,
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.backends import default_backend
from ..rfc7517 import AsymmetricKey, load_pem_key, dump_pem_key
from ..rfc7517.types import DictKey, RawKey, KeyOptions
from .._util import to_bytes, int_to_base64, base64_to_int


NativeRSAKey = Union[RSAPublicKey, RSAPrivateKeyWithSerialization]


class RSAKey(AsymmetricKey):
    key_type: str = 'RSA'
    required_fields: FrozenSet[str] = frozenset(['kty', 'e', 'n'])
    private_only_fields = frozenset(['d', 'p', 'q', 'dp', 'dq', 'qi'])

    @property
    def raw_key(self) -> NativeRSAKey:
        return self.value

    def get_op_key(self, operation: str) -> NativeRSAKey:
        self.check_key_op(operation)
        if operation in self.private_key_ops:
            return self.private_key
        return self.public_key

    def as_bytes(self, encoding=None, private=None, password=None) -> bytes:
        if private is True:
            return dump_pem_key(self.private_key, encoding, private, password)
        elif private is False:
            return dump_pem_key(self.public_key, encoding, private, password)
        return dump_pem_key(self.raw_key, encoding, self.is_private, password)

    def as_dict(self, private=None, **params) -> DictKey:
        if private is True and not self.is_private:
            raise ValueError("This is a public RSA key")

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
        return isinstance(self.value, RSAPrivateKeyWithSerialization)

    @cached_property
    def public_key(self) -> RSAPublicKey:
        if isinstance(self.value, RSAPrivateKeyWithSerialization):
            return self.value.public_key()
        return self.value

    @property
    def private_key(self) -> Optional[RSAPrivateKeyWithSerialization]:
        if self.is_private:
            return self.value
        return None

    @classmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None) -> 'RSAKey':
        if isinstance(value, dict):
            tokens = cls.validate_tokens(value)
            if 'd' in value:
                raw_key = import_private_key(value)
            else:
                raw_key = import_public_key(value)
            return cls(raw_key, options, tokens)

        if isinstance(value, str):
            value = to_bytes(value)
        raw_key = load_pem_key(value, b'ssh-rsa')
        return cls(raw_key, options)

    @classmethod
    def generate_key(cls, key_size: int=2048, options: KeyOptions=None, private=False) -> 'RSAKey':
        if key_size < 512:
            raise ValueError('key_size must not be less than 512')
        if key_size % 8 != 0:
            raise ValueError('Invalid key_size for RSAKey')
        raw_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        if not private:
            raw_key = raw_key.public_key()
        return cls(raw_key, options)


def import_private_key(obj: DictKey) -> RSAPrivateKeyWithSerialization:
    if 'oth' in obj:  # pragma: no cover
        # https://tools.ietf.org/html/rfc7518#section-6.3.2.7
        raise ValueError('"oth" is not supported yet')

    public_numbers = RSAPublicNumbers(
        base64_to_int(obj['e']), base64_to_int(obj['n']))

    if has_all_prime_factors(obj):
        numbers = RSAPrivateNumbers(
            d=base64_to_int(obj['d']),
            p=base64_to_int(obj['p']),
            q=base64_to_int(obj['q']),
            dmp1=base64_to_int(obj['dp']),
            dmq1=base64_to_int(obj['dq']),
            iqmp=base64_to_int(obj['qi']),
            public_numbers=public_numbers)
    else:
        d = base64_to_int(obj['d'])
        p, q = rsa_recover_prime_factors(
            public_numbers.n, d, public_numbers.e)
        numbers = RSAPrivateNumbers(
            d=d,
            p=p,
            q=q,
            dmp1=rsa_crt_dmp1(d, p),
            dmq1=rsa_crt_dmq1(d, q),
            iqmp=rsa_crt_iqmp(p, q),
            public_numbers=public_numbers)

    return numbers.private_key(default_backend())


def export_private_key(key: RSAPrivateKeyWithSerialization) -> Dict[str, str]:
    numbers = key.private_numbers()
    return {
        'n': int_to_base64(numbers.public_numbers.n),
        'e': int_to_base64(numbers.public_numbers.e),
        'd': int_to_base64(numbers.d),
        'p': int_to_base64(numbers.p),
        'q': int_to_base64(numbers.q),
        'dp': int_to_base64(numbers.dmp1),
        'dq': int_to_base64(numbers.dmq1),
        'qi': int_to_base64(numbers.iqmp)
    }


def import_public_key(obj: DictKey) -> RSAPublicKey:
    numbers = RSAPublicNumbers(
        base64_to_int(obj['e']),
        base64_to_int(obj['n'])
    )
    return numbers.public_key(default_backend())


def export_public_key(key: RSAPublicKey) -> Dict[str, str]:
    numbers = key.public_numbers()
    return {
        'n': int_to_base64(numbers.n),
        'e': int_to_base64(numbers.e)
    }


def has_all_prime_factors(obj) -> bool:
    props = ['p', 'q', 'dp', 'dq', 'qi']
    props_found = [prop in obj for prop in props]
    if all(props_found):
        return True

    if any(props_found):
        raise ValueError(
            'RSA key must include all parameters '
            'if any are present besides d')

    return False
