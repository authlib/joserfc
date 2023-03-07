from typing import Optional, AnyStr
from .rfc7516 import types
from .rfc7516.types import Header, EncryptionData, Recipient, JSONSerialization
from .rfc7516.registry import (
    JWERegistry,
    default_registry,
)
from .rfc7516.message import perform_encrypt, perform_decrypt
from .rfc7516.compact import represent_compact, extract_compact
from .rfc7516.json import represent_json, extract_json
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
        registry: Optional[JWERegistry]=None) -> bytes:

    if registry is None:
        registry = default_registry

    obj = EncryptionData(protected, payload)
    recipient = Recipient(obj)
    key = guess_key(public_key, recipient)
    recipient.recipient_key = key
    obj.recipients.append(recipient)
    obj.compact = True
    perform_encrypt(obj, registry)
    return represent_compact(obj)


def decrypt_compact(
        value: AnyStr,
        private_key: KeyFlexible,
        registry: Optional[JWERegistry]=None) -> EncryptionData:

    value = to_bytes(value)
    obj = extract_compact(value)
    if registry is None:
        registry = default_registry

    recipient = obj.recipients[0]
    key = guess_key(private_key, recipient)
    recipient.recipient_key = key
    return perform_decrypt(obj, registry)


def encrypt_json(
        obj: EncryptionData,
        public_key: KeyFlexible,
        registry: Optional[JWERegistry]=None) -> JSONSerialization:

    if registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        if not recipient.recipient_key:
            recipient.recipient_key = guess_key(public_key, recipient)

    perform_encrypt(obj, registry)
    return represent_json(obj)


def decrypt_json(
        data: JSONSerialization,
        private_key: KeyFlexible,
        registry: Optional[JWERegistry]=None) -> EncryptionData:

    obj = extract_json(data)
    if registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        recipient.recipient_key = guess_key(private_key, recipient)

    return perform_decrypt(obj, registry)
