import typing as t
from abc import ABCMeta, abstractmethod
from .types import KeyDict, KeyAny, KeyOptions


class _KeyMixin(object):
    key_type: str = 'oct'
    required_fields = frozenset(['kty'])
    private_key_ops = frozenset(['sign', 'decrypt', 'unwrapKey'])
    public_key_ops = frozenset(['verify', 'encrypt', 'wrapKey'])

    def __init__(self, value, options: KeyOptions=None, tokens: t.Optional[KeyDict]=None):
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
    def kid(self) -> t.Optional[str]:
        return self._kid

    @kid.setter
    def kid(self, kid: str):
        self._kid = kid

    @property
    def is_private(self) -> bool:
        return False

    @property
    def tokens(self) -> KeyDict:
        if self._tokens is None:
            self._tokens = self.as_dict()
        return self._tokens

    def as_dict(self) -> KeyDict:
        raise NotImplementedError()

    @classmethod
    def validate_tokens(cls, tokens: KeyDict):
        if not set(tokens.keys()).issuperset(cls.required_fields):
            raise ValueError("Missing required fields")
        if tokens['kty'] != cls.key_type:
            raise ValueError("Mismatching `kty` value")

    def render_tokens(self, tokens: KeyDict) -> KeyDict:
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
            raise ValueError(f'Unsupported key_op "{operation}"')

        if operation in self.private_key_ops and not self.is_private:
            raise ValueError(f'Invalid key_op "{operation}" for public key')

    def check_use(self, use: str) -> None:
        """Check if the given "use" is supported by this key.

        :param use: key use value, such as "sig", "enc".
        :raise: ValueError
        """
        # only check key in JSON(dict) format
        if self._tokens is None:
            return

        key_use = self._tokens.get('use')
        if key_use is not None and key_use != use:
            raise ValueError(f'Unsupported use of "{use}"')


class SymmetricKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'oct'

    @property
    def raw_key(self) -> bytes:
        return self.value

    @property
    def is_private(self) -> bool:
        return True

    @abstractmethod
    def as_dict(self, **params) -> KeyDict:
        pass

    @abstractmethod
    def get_op_key(self, operation: str):
        pass

    @classmethod
    @abstractmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, key_size: int, options: KeyOptions = None, private: bool=True):
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
    def as_dict(self, private=None, **params) -> KeyDict:
        pass

    @abstractmethod
    def as_bytes(
            self,
            encoding: t.Optional[str]=None,
            private: t.Optional[bool]=None,
            password: t.Optional[str]=None) -> bytes:
        pass

    def as_pem(self, private=None, password=None) -> bytes:
        return self.as_bytes(private=private, password=password)

    def as_der(self, private=None, password=None) -> bytes:
        return self.as_bytes(encoding='DER', private=private, password=password)

    @classmethod
    @abstractmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, key_size: int, options: KeyOptions = None, private: bool=True):
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
    def as_dict(self, private=None, **params) -> KeyDict:
        pass

    @classmethod
    @abstractmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None):
        pass

    @classmethod
    @abstractmethod
    def generate_key(cls, crv: str, options: KeyOptions=None, private: bool=True):
        pass


Key = t.Union[SymmetricKey, AsymmetricKey, CurveKey]
