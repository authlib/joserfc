import typing as t
from .rfc7516 import types
from .rfc7516.types import JSONSerialization
from .rfc7516.models import (
    Recipient,
    CompactEncryption,
    JSONEncryption,
    JWEEncModel,
    JWEZipModel,
)
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
from .jwk import CurveKey, KeySet, KeyFlexible, guess_key
from .util import to_bytes
from .registry import Header

__all__ = [
    "types",
    "JWERegistry",
    "JWEEncModel",
    "JWEZipModel",
    "Recipient",
    "CompactEncryption",
    "JSONEncryption",
    "encrypt_compact",
    "decrypt_compact",
    "extract_compact",
    "encrypt_json",
    "decrypt_json",
    "default_registry",
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
        plaintext: bytes,
        public_key: KeyFlexible,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[CurveKey] = None) -> bytes:

    if registry is None:
        registry = default_registry

    obj = CompactEncryption(protected, plaintext)
    recipient = Recipient(obj)
    key = guess_key(public_key, recipient)
    recipient.recipient_key = key
    recipient.sender_key = sender_key
    obj.recipient = recipient
    perform_encrypt(obj, registry)
    return represent_compact(obj)


def decrypt_compact(
        value: t.AnyStr,
        private_key: KeyFlexible,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[CurveKey] = None) -> CompactEncryption:

    value = to_bytes(value)
    obj = extract_compact(value)
    if registry is None:
        registry = default_registry

    recipient = obj.recipient
    recipient.recipient_key = guess_key(private_key, recipient)
    recipient.sender_key = sender_key
    return perform_decrypt(obj, registry)


def encrypt_json(
        obj: JSONEncryption,
        public_key: KeyFlexible,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[t.Union[CurveKey, KeySet]] = None) -> JSONSerialization:
    if registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        if sender_key and not recipient.sender_key:
            recipient.sender_key = _guess_sender_key(recipient, sender_key)
        if not recipient.recipient_key:
            recipient.recipient_key = guess_key(public_key, recipient)

    perform_encrypt(obj, registry)
    return represent_json(obj)


def decrypt_json(
        data: JSONSerialization,
        private_key: KeyFlexible,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[t.Union[CurveKey, KeySet]] = None) -> JSONEncryption:
    obj = extract_json(data)
    if registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        recipient.recipient_key = guess_key(private_key, recipient)
        if sender_key:
            recipient.sender_key = _guess_sender_key(recipient, sender_key)

    return perform_decrypt(obj, registry)


def _guess_sender_key(recipient, key: t.Union[CurveKey, KeySet]):
    if isinstance(key, KeySet):
        header = recipient.headers()
        skid = header.get('skid')
        if skid:
            return key.get_by_kid(skid)
        return None
    return key
