import typing as t
from .rfc7518.oct_key import OctKey
from .rfc7518.rsa_key import RSAKey
from .rfc7518.ec_key import ECKey
from .rfc8037.okp_key import OKPKey

Key = t.Union[OctKey, RSAKey, ECKey, OKPKey]


__all__ = [
    "OctKey",
    "RSAKey",
    "ECKey",
    "OKPKey",
]
