import typing as t
from collections import namedtuple

Header = t.Dict[str, t.Any]


def is_str(value: str):
    if not isinstance(value, str):
        raise ValueError("must be a str")


def is_url(value: str):
    is_str(value)
    if not value.startswith(("http://", "https://")):
        raise ValueError("must be a URL")


def is_int(value: int):
    if not isinstance(value, int):
        raise ValueError("must be an int")


def is_bool(value: bool):
    if not isinstance(value, bool):
        raise ValueError("must be an bool")


def is_list_str(values):
    if not isinstance(values, list):
        raise ValueError("must be a list[str]")

    for value in values:
        if not isinstance(value, str):
            raise ValueError("must be a list[str]")


def is_jwk(value):
    if not isinstance(value, dict):
        raise ValueError("must be a JWK")


def in_choices(choices: t.List[str]):
    def _is_one_of(value):
        if isinstance(value, list):
            for v in value:
                if v not in choices:
                    raise ValueError(f"must be one of {choices}")

        elif value not in choices:
            raise ValueError(f"must be one of {choices}")

    return _is_one_of


def not_support(_):
    raise ValueError("is not supported")


Validate = t.Callable[[t.Any], t.NoReturn]
_value_validators = {
    "str": is_str,
    "list[str]": is_list_str,
    "int": is_int,
    "bool": is_bool,
    "url": is_url,
    "jwk": is_jwk,
    "none": not_support,
}

class HeaderParameter:
    def __init__(self, description: str, validate: t.Union[str, Validate], required: bool=False):
        self.description: str = description
        if isinstance(validate, str):
            self.validate: Validate = _value_validators[validate]
        else:
            self.validate: Validate = validate
        self.required = required

#: Define header parameters for JWS and JWE
HeaderRegistryDict = t.Dict[str, HeaderParameter]


class KeyParameter:
    def __init__(
            self,
             description: str,
             validate: t.Union[str, Validate],
             private: t.Optional[bool]=None,
             required: bool=False):
        self.description: str = description
        if isinstance(validate, str):
            self.validate: Validate = _value_validators[validate]
        else:
            self.validate: Validate = validate
        self.private = private
        self.required = required

#: Define parameters for JWK
KeyParameterRegistryDict = t.Dict[str, KeyParameter]
KeyOperation = namedtuple("KeyOperation", ["description", "use", "private"])
KeyOperationRegistryDict = t.Dict[str, KeyOperation]

#: Basic JWS header registry
JWS_HEADER_REGISTRY: HeaderRegistryDict = {
    "alg": HeaderParameter("Algorithm", is_str, True),
    "jku": HeaderParameter("JWK Set URL", is_url),
    "jwk": HeaderParameter("JSON Web Key",  is_jwk),
    "kid": HeaderParameter("Key ID", is_str),
    "x5u": HeaderParameter("X.509 URL", is_url),
    "x5c": HeaderParameter("X.509 Certificate Chain", is_list_str),
    "x5t": HeaderParameter("X.509 Certificate SHA-1 Thumbprint", is_str),
    "x5t#S256": HeaderParameter("X.509 Certificate SHA-256 Thumbprint", is_str),
    "typ": HeaderParameter("Type", is_str),
    "cty": HeaderParameter("Content Type", is_str),
    "crit": HeaderParameter("Critical", is_list_str),
}

#: Basic JWE header registry
JWE_HEADER_REGISTRY = {
    "enc": HeaderParameter("Encryption Algorithm", is_str, True),
    "zip": HeaderParameter("Compression Algorithm", is_str),
    **JWS_HEADER_REGISTRY,
}

#: Basic JWK parameter registry
JWK_PARAMETER_REGISTRY = {
    "kty": KeyParameter("Key ID", is_str, required=True),  # This member MUST be present in a JWK.
    "use": KeyParameter("Public Key Use", in_choices(["sig", "enc"])),
    "key_ops": KeyParameter(
        "Key Operations",
        in_choices([
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ]),
    ),
    "alg": KeyParameter("Algorithm", is_str),
    "kid": KeyParameter("Key ID", is_str),
    "x5u": KeyParameter("X.509 URL", is_url),
    "x5c": KeyParameter("X.509 Certificate Chain", is_list_str),
    "x5t": KeyParameter("X.509 Certificate SHA-1 Thumbprint", is_str),
    "x5t#S256": KeyParameter("X.509 Certificate SHA-256 Thumbprint", is_str),
}

#: Common JWK operations
#: https://www.rfc-editor.org/rfc/rfc7517#section-4.3
JWK_OPERATION_REGISTRY = {
    "sign": KeyOperation("compute digital signature or MAC", "sig", True),
    "verify": KeyOperation("verify digital signature or MAC", "sig", False),
    "encrypt": KeyOperation("encrypt content", "enc", False),
    "decrypt": KeyOperation("decrypt content and validate decryption, if applicable", "enc", True),
    "wrapKey": KeyOperation("encrypt key", "enc", False),
    "unwrapKey": KeyOperation("decrypt key and validate decryption, if applicable", "enc", True),
    "deriveKey": KeyOperation("derive key", "enc", False),
    "deriveBits": KeyOperation("derive bits not to be used as a key", "enc", None),
}


def check_supported_header(registry: HeaderRegistryDict, header: Header):
    allowed_keys = set(registry.keys())
    unsupported_keys = set(header.keys()) - allowed_keys
    if unsupported_keys:
        raise ValueError(f'Unsupported "{unsupported_keys} in header')


def check_registry_header(registry: HeaderRegistryDict, header: Header):
    for key in registry:
        reg: HeaderParameter = registry[key]
        if reg.required and key not in header:
            raise ValueError(f'Required "{key}" is missing in header')
        if key in header:
            try:
                reg.validate(header[key])
            except ValueError as error:
                raise ValueError(f'"{key}" in header {error}')


def check_crit_header(header: Header):
    # check crit header
    if "crit" in header:
        for k in header["crit"]:
            if k not in header:
                raise ValueError(f'"{k}" is a critical header')
