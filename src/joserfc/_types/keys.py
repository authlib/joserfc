from typing import Optional, Union, Dict
from abc import ABCMeta, abstractmethod
from functools import cached_property


KeyOptions = Optional[Dict[str, str]]


class _KeyMixin(object):
    key_type: str = 'oct'

    def __init__(self, value, options: KeyOptions=None):
        self.value = value
        self.options = options or {}

    @property
    def kty(self) -> str:
        return self.key_type

    @abstractmethod
    def get_op_key(self, operation: str):
        pass


class PlainKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'oct'
    is_private: bool = True

    @cached_property
    def tokens(self) -> Dict[str, str]:
        return self.as_dict()

    @abstractmethod
    def as_dict(self) -> Dict[str, str]:
        pass


class AsymmetricKey(_KeyMixin, metaclass=ABCMeta):
    key_type: str = 'RSA'

    @cached_property
    def tokens(self) -> Dict[str, str]:
        return self.as_dict()

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
    def as_dict(self, private=None) -> Dict[str, str]:
        pass

    @abstractmethod
    def as_bytes(self, encoding=None, private=None, password=None) -> bytes:
        pass

    def as_pem(self, private=None, password=None) -> bytes:
        return self.as_bytes(private=private, password=password)

    def as_der(self, private=None, password=None) -> bytes:
        return self.as_bytes(encoding='DER', private=private, password=password)


Key = Union[PlainKey, AsymmetricKey]
