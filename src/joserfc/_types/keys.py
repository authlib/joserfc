from typing import Optional, Union, Dict, FrozenSet
from abc import ABCMeta, abstractmethod


KeyOptions = Optional[Dict[str, str]]
RawKey = Union[str, bytes, Dict[str, str]]


class _KeyMixin(object):
    key_type: str = 'oct'
    required_fields: FrozenSet[str] = frozenset(['kty'])
    private_key_ops: FrozenSet[str] = frozenset(['sign', 'decrypt', 'unwrapKey'])
    public_key_ops: FrozenSet[str] = frozenset(['verify', 'encrypt', 'wrapKey'])

    def __init__(self, value, options: KeyOptions=None):
        self.value = value
        self.options = options or {}
        self._tokens = None

    @property
    def kty(self) -> str:
        return self.key_type

    @property
    def is_private(self) -> bool:
        return False

    @property
    def tokens(self) -> Dict[str, str]:
        if self._tokens is None:
            self._tokens = self.as_dict()
        return self._tokens

    @classmethod
    def validate_tokens(cls, tokens: Dict[str, str]):
        if not set(tokens.keys()).issuperset(self.required_fields):
            raise ValueError("Missing required fields")
        if tokens['kty'] != self.key_type:
            raise ValueError("Mismatching `kty` value")
        return tokens


    def check_key_op(self, operation: str):
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


class PlainKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'oct'

    @property
    def is_private(self) -> bool:
        return True

    @abstractmethod
    def as_dict(self, **params) -> Dict[str, str]:
        pass

    @abstractmethod
    def get_op_key(self, operation: str):
        pass

    @classmethod
    @abstractmethod
    def import_key(cls, value: RawKey, options: KeyOptions=None):
        pass


class AsymmetricKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'RSA'

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
    def as_dict(self, private=None, **params) -> Dict[str, str]:
        pass

    @abstractmethod
    def as_bytes(self, encoding=None, private=None, password=None) -> bytes:
        pass

    def as_pem(self, private=None, password=None) -> bytes:
        return self.as_bytes(private=private, password=password)

    def as_der(self, private=None, password=None) -> bytes:
        return self.as_bytes(encoding='DER', private=private, password=password)


Key = Union[PlainKey, AsymmetricKey]
