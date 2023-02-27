import binascii
from .types import EncryptionData, Recipient
from .registry import JWERegistry
from .message import perform_encrypt, perform_decrypt
from ..errors import (
    MissingAlgorithmError,
    MissingEncryptionError,
    DecodeError,
)
from ..util import (
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def encrypt_compact(obj: EncryptionData, registry: JWERegistry) -> bytes:
    perform_encrypt(obj, registry)
    return represent_compact(obj)


def represent_compact(obj: EncryptionData) -> bytes:
    recipient = obj.recipients[0]
    return b'.'.join([
        obj.encoded['aad'],
        urlsafe_b64encode(recipient.encrypted_key),
        obj.encoded['iv'],
        urlsafe_b64encode(obj.decoded['ciphertext']),
        urlsafe_b64encode(obj.decoded['tag'])
    ])


def extract_compact(value: bytes) -> EncryptionData:
    parts = value.split(b'.')
    if len(parts) != 5:
        raise ValueError('Invalid JSON Web Encryption')

    header_segment, ek_segment, iv_segment, ciphertext_segment, tag_segment = parts
    try:
        protected = json_b64decode(header_segment)
        if 'alg' not in protected:
            raise MissingAlgorithmError()
        if 'enc' not in protected:
            raise MissingEncryptionError()
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid header')

    obj = EncryptionData(protected)
    obj.compact = True
    obj.encoded.update({
        'aad': header_segment,
        'iv': iv_segment,
        'ciphertext': ciphertext_segment,
        'tag': tag_segment,
    })
    obj.decoded.update({
        'iv': urlsafe_b64decode(iv_segment),
        'ciphertext': urlsafe_b64decode(ciphertext_segment),
        'tag': urlsafe_b64decode(tag_segment),
    })
    recipient = Recipient(obj)
    recipient.encrypted_key = urlsafe_b64decode(ek_segment)
    obj.recipients.append(recipient)
    return obj


def decrypt_compact(obj: EncryptionData, registry: JWERegistry) -> EncryptionData:
    if not obj.compact or len(obj.recipients) != 1:
        raise ValueError("Invalid encryption data")

    perform_decrypt(obj, registry)
    return obj
