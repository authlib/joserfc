from typing import Optional, AnyStr
from .rfc7516 import types
from .rfc7516.types import Header, EncryptionData, Recipient
from .rfc7516.registry import (
    JWERegistry,
    default_registry,
)
from .rfc7516.compact import (
    extract_compact,
    encrypt_compact as _encrypt_compact,
    decrypt_compact as _decrypt_compact,
)
from .rfc7518.jwe_algs import JWE_ALG_MODELS
from .rfc7518.jwe_encs import JWE_ENC_MODELS
from .rfc7518.jwe_zips import JWE_ZIP_MODELS
from .jwk import KeyFlexible, guess_key
from .util import to_bytes


__all__ = [
    'types',
    'JWERegistry',
    'encrypt_compact',
    'decrypt_compact',
    'extract_compact',
]

def __register():
    for _alg in JWE_ALG_MODELS:
        JWERegistry.register(_alg)

    for _enc in JWE_ENC_MODELS:
        JWERegistry.register(_enc)

    for _zip in JWE_ZIP_MODELS:
        JWERegistry.register(_zip)

__register()


def encrypt_compact(
        protected: Header,
        payload: bytes,
        public_key: KeyFlexible,
        registry: Optional[JWERegistry]=None,
        sender_key=None) -> bytes:
    if registry is None:
        registry = default_registry
    registry.check_header(protected)
    recipient = Recipient(protected)
    wrap_key = guess_key(public_key, recipient, 'wrapKey')
    obj = EncryptionData(protected, payload)
    obj.compact = True
    return _encrypt_compact(obj, wrap_key, registry, sender_key)


def decrypt_compact(
        value: AnyStr,
        private_key: KeyFlexible,
        registry: Optional[JWERegistry]=None,
        sender_key=None) -> EncryptionData:
    value = to_bytes(value)
    obj = extract_compact(value)
    if registry is None:
        registry = default_registry
    registry.check_header(obj.protected, True)
    unwrap_key = guess_key(private_key, obj.recipients[0], 'unwrapKey')
    return _decrypt_compact(obj, unwrap_key, registry, sender_key)
