from typing import (
    Optional,
    Union,
    Dict,
    List,
    FrozenSet,
    TypedDict,
    Callable,
)
from abc import ABCMeta, abstractmethod
from .pem import dump_pem_key
from .types import DictKey, RawKey, KeyOptions


class _KeyMixin(object):
    key_type: str = 'oct'
    required_fields: FrozenSet[str] = frozenset(['kty'])
    private_key_ops: FrozenSet[str] = frozenset(['sign', 'decrypt', 'unwrapKey'])
    public_key_ops: FrozenSet[str] = frozenset(['verify', 'encrypt', 'wrapKey'])

    def __init__(self, value, options: KeyOptions=None, tokens: Optional[DictKey]=None):
        self.value = value
        self.options = options or {}
        if tokens is not None:
            if 'kty' in tokens and tokens['kty'] != self.kty:
                raise ValueError(f'Invalid key for type "{self.kty}"')

            _tokens = {'kty': self.kty}
            _tokens.update(self.options)
            _tokens.update(tokens)
            self._tokens = _tokens
            self._kid = tokens.get('kid')
        else:
            self._tokens = None
            self._kid = None

    def keys(self):
        return self.tokens.keys()

    def __getitem__(self, k):
        return self.tokens[k]

    @property
    def kty(self) -> str:
        return self.key_type

    @property
    def kid(self) -> Optional[str]:
        return self._kid

    @kid.setter
    def kid(self, kid: str):
        self._kid = kid

    @property
    def is_private(self) -> bool:
        return False

    @property
    def tokens(self) -> DictKey:
        if self._tokens is None:
            self._tokens = self.as_dict()
        return self._tokens

    @classmethod
    def validate_tokens(cls, tokens: DictKey):
        if not set(tokens.keys()).issuperset(cls.required_fields):
            raise ValueError("Missing required fields")
        if tokens['kty'] != cls.key_type:
            raise ValueError("Mismatching `kty` value")
        return tokens

    def render_tokens(self, tokens: DictKey) -> DictKey:
        if self.options:
            tokens.update(self.options)
        if self.kid:
            tokens['kid'] = self.kid
        tokens['kty'] = self.kty
        return tokens

    def check_key_op(self, operation: str) -> None:
        """Check if the given key_op is supported by this key.

        :param operation: key operation value, such as "sign", "encrypt".
        :raise: ValueError
        """
        # only check key in JSON(dict) format
        if self._tokens is None:
            return

        key_ops = self._tokens.get('key_ops')
        if key_ops is not None and operation not in key_ops:
            raise ValueError('Unsupported key_op "{}"'.format(operation))

        if operation in self.private_key_ops and not self.is_private:
            raise ValueError('Invalid key_op "{}" for public key'.format(operation))


class SymmetricKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'oct'

    @property
    def raw_key(self) -> bytes:
        return self.value

    @property
    def is_private(self) -> bool:
        return True

    @abstractmethod
    def as_dict(self, **params) -> DictKey:
        pass

    @abstractmethod
    def get_op_key(self, operation: str):
        pass

    @classmethod
    @abstractmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, key_size: int, options: KeyOptions = None, private=False):
        pass


class AsymmetricKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'RSA'

    @property
    def raw_key(self):
        return self.value

    @property
    @abstractmethod
    def is_private(self):
        pass

    @property
    @abstractmethod
    def public_key(self):
        pass

    @property
    @abstractmethod
    def private_key(self):
        pass

    @abstractmethod
    def get_op_key(self, operation: str):
        pass

    @abstractmethod
    def as_dict(self, private=None, **params) -> DictKey:
        pass

    def as_bytes(self,
                 encoding: Optional[str]=None,
                 private: Optional[bool]=None,
                 password: Optional[str]=None) -> bytes:
        if private is True:
            return dump_pem_key(self.private_key, encoding, private, password)
        elif private is False:
            return dump_pem_key(self.public_key, encoding, private, password)
        return dump_pem_key(self.raw_key, encoding, self.is_private, password)

    def as_pem(self, private=None, password=None) -> bytes:
        return self.as_bytes(private=private, password=password)

    def as_der(self, private=None, password=None) -> bytes:
        return self.as_bytes(encoding='DER', private=private, password=password)

    @classmethod
    @abstractmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, key_size: int, options: KeyOptions = None, private=False):
        pass


class CurveKey(AsymmetricKey):
    key_type: str = 'EC'

    @abstractmethod
    def exchange_shared_key(self, pubkey):
        pass

    @property
    @abstractmethod
    def is_private(self):
        pass

    @property
    @abstractmethod
    def public_key(self):
        pass

    @property
    @abstractmethod
    def private_key(self):
        pass

    @abstractmethod
    def get_op_key(self, operation: str):
        pass

    @abstractmethod
    def as_dict(self, private=None, **params) -> DictKey:
        pass

    @classmethod
    @abstractmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, crv: str, options: KeyOptions=None, private=False):
        pass


#: Key type for all SymmetricKey, AsymmetricKey, and CurveKey
Key = Union[SymmetricKey, AsymmetricKey, CurveKey]

#: registry to store all registered keys
JWK_REGISTRY: Dict[str, Key] = {}


class KeySet:
    thumbprint: Optional[Callable[[Key], str]] = None

    def __init__(self, keys: List[Key]):
        self.keys = keys

    def as_dict(self):
        keys = []

        for key in self.keys:
            if self.thumbprint is not None and key.kid is None:
                key.kid = self.thumbprint(key)

            keys.append(key.tokens)

        return {"keys": keys}

    @classmethod
    def import_key(cls, keys: List[DictKey], options: KeyOptions=None) -> 'KeySet':
        rv = []

        for _key in keys:
            kty = _key['kty']
            key_cls = JWK_REGISTRY[kty]
            key = key_cls.import_key(_key, options)
            rv.append(key)

        return cls(rv)
