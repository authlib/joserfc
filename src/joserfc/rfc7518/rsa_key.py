from typing import Optional, Union, Dict
from functools import cached_property
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKeyWithSerialization,
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.backends import default_backend
from ..registry import KeyParameter, is_str, not_support
from ..rfc7517.models import AsymmetricKey
from ..rfc7517.pem import CryptographyBinding
from ..rfc7517.types import KeyDict, KeyOptions
from ..util import int_to_base64, base64_to_int

NativeRSAKey = Union[RSAPublicKey, RSAPrivateKeyWithSerialization]


class RSABinding(CryptographyBinding):
    ssh_type = b'ssh-rsa'

    @staticmethod
    def import_private_key(obj: KeyDict) -> RSAPrivateKeyWithSerialization:
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

    @staticmethod
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

    @staticmethod
    def import_public_key(obj: KeyDict) -> RSAPublicKey:
        numbers = RSAPublicNumbers(
            base64_to_int(obj['e']),
            base64_to_int(obj['n'])
        )
        return numbers.public_key(default_backend())

    @staticmethod
    def export_public_key(key: RSAPublicKey) -> Dict[str, str]:
        numbers = key.public_numbers()
        return {
            'n': int_to_base64(numbers.n),
            'e': int_to_base64(numbers.e)
        }


class RSAKey(AsymmetricKey):
    key_type: str = 'RSA'
    #: Registry definition for RSA Key
    #: https://www.rfc-editor.org/rfc/rfc7518#section-6.3
    value_registry = {
        'n': KeyParameter('Modulus', True, False, is_str),
        'e': KeyParameter('Exponent', True, False, is_str),
        'd': KeyParameter('Private Exponent', False, True, is_str),
        'p': KeyParameter('First Prime Factor', False, True, is_str),
        'q': KeyParameter('Second Prime Factor', False, True, is_str),
        'dp': KeyParameter('First Factor CRT Exponent', False, True, is_str),
        'dq': KeyParameter('Second Factor CRT Exponent', False, True, is_str),
        'qi': KeyParameter('First CRT Coefficient', False, True, is_str),
        'oth': KeyParameter('Other Primes Info', False, True, not_support),
    }
    binding = RSABinding

    @property
    def raw_value(self) -> NativeRSAKey:
        return self._raw_value

    @property
    def is_private(self) -> bool:
        return isinstance(self.raw_value, RSAPrivateKeyWithSerialization)

    @cached_property
    def public_key(self) -> RSAPublicKey:
        if isinstance(self.raw_value, RSAPrivateKeyWithSerialization):
            return self.raw_value.public_key()
        return self.raw_value

    @property
    def private_key(self) -> Optional[RSAPrivateKeyWithSerialization]:
        if self.is_private:
            return self.raw_value
        return None

    @classmethod
    def generate_key(
            cls,
            key_size: int=2048,
            options: KeyOptions=None,
            private: bool=True) -> 'RSAKey':
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
        return cls(raw_key, raw_key, options)


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
