import typing as t
from .models import Key
from .types import KeyAny, KeyParameters
from ..util import to_bytes


class JWKRegistry:
    """A registry for JWK to record ``joserfc`` supported key types.
    Normally, you would use explicit key types like ``OctKey``, ``RSAKey``;
    This registry provides a way to dynamically import and generate keys.
    For instance:

    .. code-block:: python

        # instead of choosing which key type to use yourself,
        # JWKRegistry can import it automatically
        data = {"kty": "oct", "k": "..."}
        key = JWKRegistry.import_key(data)
    """
    key_types: t.Dict[str, t.Type[Key]] = {}

    @classmethod
    def register(cls, model: t.Type[Key]):
        cls.key_types[model.key_type] = model

    @classmethod
    def import_key(cls, data: KeyAny, key_type: t.Optional[str] = None, parameters: KeyParameters = None) -> Key:
        """A class method for importing a key from bytes, string, and dict.
        When ``value`` is a dict, this method can tell the key type automatically,
        otherwise, developers SHOULD pass the ``key_type`` themselves.

        :param data: the key data in bytes, string, or dict.
        :param key_type: an optional key type in string.
        :param parameters: extra key parameters
        :return: OctKey, RSAKey, ECKey, or OKPKey
        """
        if isinstance(data, dict) and key_type is None:
            if "kty" not in data:
                raise ValueError("Missing key type")
            key_type = data["kty"]

        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        if isinstance(data, str):
            data = to_bytes(data)

        key_cls = cls.key_types[key_type]
        return key_cls.import_key(data, parameters)  # type: ignore

    @classmethod
    def generate_key(
            cls,
            key_type: str,
            crv_or_size: t.Union[str, int],
            parameters: KeyParameters = None,
            private: bool = True) -> Key:
        """A class method for generating key according to the given key type.
        When ``key_type`` is "oct" and "RSA", the second parameter SHOULD be
        a key size in bits. When ``key_type`` is "EC" and "OKP", the second
        parameter SHOULD be a "crv" string.

        .. code-block:: python

            JWKRegistry.generate_key("RSA", 2048)
            JWKRegistry.generate_key("EC", "P-256")
        """
        if key_type not in cls.key_types:
            raise ValueError(f'Invalid key type: "{key_type}"')

        key_cls = cls.key_types[key_type]
        return key_cls.generate_key(crv_or_size, parameters, private)  # type: ignore
