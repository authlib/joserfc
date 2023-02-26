import typing as t
from abc import ABCMeta, abstractmethod
from .types import KeyDict, KeyAny, KeyOptions
from ..registry import (
    KeyParameterRegistryDict,
    JWK_PARAMETER_REGISTRY,
    KeyOperationRegistryDict,
    JWK_OPERATION_REGISTRY,
)
from ..util import to_bytes
from ..rfc7638 import thumbprint

if hasattr(t, 'Self'):
    SelfKey = t.Self
else:
    SelfKey = t.TypeVar('SelfKey', bound='BaseKey')


class NativeKeyBinding(object, metaclass=ABCMeta):
    use_key_ops_registry = {
        'sig': ['sign', 'verify'],
        'enc': ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits']
    }

    @classmethod
    @abstractmethod
    def convert_raw_key_to_dict(cls, raw_key, private: bool) -> KeyDict:
        pass

    @classmethod
    @abstractmethod
    def import_from_dict(cls, value: KeyDict):
        pass

    @classmethod
    @abstractmethod
    def import_from_bytes(cls, value: bytes):
        pass

    @staticmethod
    def as_bytes(key: 'BaseKey', encoding=None, private=None, password=None) -> bytes:
        return key.raw_value

    @classmethod
    def validate_dict_key_registry(cls, dict_key: KeyDict, registry: KeyParameterRegistryDict):
        for k in registry:
            if registry[k].required and k not in dict_key:
                raise ValueError(f'"{k}" is required')

            if k in dict_key:
                try:
                    registry[k].check_value(dict_key[k])
                except ValueError as error:
                    raise ValueError(f'"{k}" {error}')

    @classmethod
    def validate_dict_key_use_operations(cls, dict_key: KeyDict):
        if 'use' in dict_key and 'key_ops' in dict_key:
            operations = cls.use_key_ops_registry[dict_key['use']]
            for op in dict_key['key_ops']:
                if op not in operations:
                    raise ValueError(f'"use" and "key_ops" does not match')


class BaseKey(object):
    key_type: str
    value_registry: KeyParameterRegistryDict
    param_registry: KeyParameterRegistryDict = JWK_PARAMETER_REGISTRY
    operation_registry: KeyOperationRegistryDict = JWK_OPERATION_REGISTRY
    binding = NativeKeyBinding

    def __init__(self, raw_value, original_value, options: KeyOptions=None):
        self._raw_value = raw_value
        self.original_value = original_value
        self.options = options
        if isinstance(original_value, dict):
            data = original_value.copy()
            data['kty'] = self.key_type
            if options:
                data.update(dict(options))

            self.validate_dict_key(data)
            self._dict_value = data
        else:
            self._dict_value = None

    def keys(self):
        return self.dict_value.keys()

    def __getitem__(self, k: str):
        return self.dict_value[k]

    def get(self, k: str, default=None):
        return self.dict_value.get(k, default)

    @property
    def kid(self) -> str:
        kid = self.get('kid')
        if not kid:
            kid = self.thumbprint()
            self._dict_value['kid'] = kid
        return kid

    @property
    def raw_value(self):
        return self._raw_value

    @property
    def is_private(self) -> bool:
        return False

    @property
    def dict_value(self) -> KeyDict:
        """Property of the Key in Dict (JSON)."""
        if self._dict_value:
            return self._dict_value

        data = self.binding.convert_raw_key_to_dict(self.raw_value, self.is_private)
        if self.options:
            data.update(dict(self.options))
        data['kty'] = self.key_type
        self.validate_dict_key(data)
        self._dict_value = data
        return data

    @property
    def public_key(self):
        raise NotImplementedError()

    @property
    def private_key(self):
        raise NotImplementedError()

    def thumbprint(self) -> str:
        """Call this method will generate the thumbprint with algorithm
        defined in RFC7638."""
        fields = [k for k in self.value_registry if self.value_registry[k].required]
        fields.append('kty')
        return thumbprint(self.dict_value, fields)

    def as_dict(self, private: t.Optional[bool]=None, **params) -> KeyDict:
        """Output this key to a JWK format (in dict). By default it will return
        the :property:`dict_value` of this key.

        :param private: determine whether this method should output private key or not
        :param params: other parameters added into this key
        :raise: ValueError
        """
        # check private conflicts
        if private and not self.is_private:
            raise ValueError("This key is not a private key.")

        data = self.dict_value.copy()
        if private is not False:
            # keep original
            return data

        # clear private fields
        for k in self.dict_value:
            if k in self.value_registry and self.value_registry[k].private:
                del data[k]

        data.update(params)
        return data

    def check_use(self, use: str):
        designed_use = self.get('use')
        if designed_use and designed_use != use:
            raise ValueError(f'This key is designed to by used for "{designed_use}"')
    def check_key_op(self, operation: str):
        """Check if the given key_op is supported by this key.

        :param operation: key operation value, such as "sign", "encrypt".
        :raise: ValueError
        """
        key_ops = self.get('key_ops')
        if key_ops is not None and operation not in key_ops:
            raise ValueError(f'Unsupported key_op "{operation}"')

        assert operation in self.operation_registry
        reg = self.operation_registry[operation]
        if reg.private and not self.is_private:
            raise ValueError(f'Invalid key_op "{operation}" for public key')

    def get_op_key(self, operation: str):
        self.check_key_op(operation)
        reg = self.operation_registry[operation]
        if reg.private:
            return self.private_key
        return self.public_key

    @classmethod
    def validate_dict_key(cls, data: KeyDict):
        cls.binding.validate_dict_key_registry(data, cls.param_registry)
        cls.binding.validate_dict_key_registry(data, cls.value_registry)
        cls.binding.validate_dict_key_use_operations(data)

    @classmethod
    def import_key(cls, value: KeyAny, options: KeyOptions=None) -> SelfKey:
        if isinstance(value, dict):
            cls.validate_dict_key(value)
            raw_key = cls.binding.import_from_dict(value)
            return cls(raw_key, value, options)

        raw_key = cls.binding.import_from_bytes(to_bytes(value))
        return cls(raw_key, value, options)

    @classmethod
    def generate_key(cls, size_or_crv, options: KeyOptions = None, private: bool=True) -> SelfKey:
        raise NotImplementedError()


class SymmetricKey(BaseKey, metaclass=ABCMeta):
    @property
    def raw_value(self) -> bytes:
        return self._raw_value

    @property
    def is_private(self) -> bool:
        return True

    @property
    def public_key(self) -> bytes:
        return self.raw_value

    @property
    def private_key(self) -> bytes:
        return self.raw_value


class AsymmetricKey(BaseKey, metaclass=ABCMeta):
    def as_bytes(
            self,
            encoding: t.Optional[str]=None,
            private: t.Optional[bool]=None,
            password: t.Optional[str]=None) -> bytes:
        return self.binding.as_bytes(self, encoding, private, password)

    def as_pem(self, private=None, password=None) -> bytes:
        return self.as_bytes(private=private, password=password)

    def as_der(self, private=None, password=None) -> bytes:
        return self.as_bytes(encoding='DER', private=private, password=password)



class CurveKey(AsymmetricKey):
    @property
    @abstractmethod
    def curve_name(self) -> str:
        pass

    @abstractmethod
    def exchange_shared_key(self, pubkey) -> bytes:
        pass


Key = t.Union[SymmetricKey, AsymmetricKey, CurveKey]
