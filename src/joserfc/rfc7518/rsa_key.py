from typing import Optional, Dict, FrozenSet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKeyWithSerialization,
    RSAPrivateNumbers, RSAPublicNumbers,
    rsa_recover_prime_factors, rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
)
from cryptography.hazmat.backends import default_backend
from .._types.keys import AsymmetricKey, DictKey, RawKey, KeyOptions
from .._util import int_to_base64, base64_to_int


class RSAKey(AsymmetricKey):
    key_type: str = 'RSA'
    required_fields: FrozenSet[str] = frozenset(['kty', 'e', 'n'])
    private_only_fields = frozenset(['d', 'p', 'q', 'dp', 'dq', 'qi'])

    def get_op_key(self, operation: str):
        return self.public_key

    def as_bytes(self, encoding=None, private=None, password=None) -> bytes:
        return b''

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

    @property
    def public_key(self) -> RSAPublicKey:
        if self.is_private():
            pass

    @property
    def private_key(self) -> Optional[RSAPrivateKeyWithSerialization]:
        if self.is_private():
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
            key = cls(raw_key, options)
            key._tokens = key.render_tokens(tokens)
            return key
        # TODO
        return None



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
