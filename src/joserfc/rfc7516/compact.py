import binascii
from .types import EncryptionData, Recipient
from .registry import JWERegistry
from ..errors import (
    MissingAlgorithmError,
    MissingEncryptionError,
    DecodeError,
)
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def encrypt_compact(
        obj: EncryptionData,
        public_key,
        registry: JWERegistry,
        sender_key=None) -> bytes:

    alg, enc, zip_ = registry.get_algorithms(obj.protected)
    recipient = Recipient()

    # Generate a random Content Encryption Key (CEK)
    if alg.key_size is not None:
        obj.cek = enc.generate_cek()

    # add cek, ek, epk
    alg.wrap(enc, obj, recipient, public_key, sender_key)

    # Generate a random JWE Initialization Vector
    obj.iv = enc.generate_iv()

    # Let the Additional Authenticated Data encryption parameter
    # be ASCII(BASE64URL(UTF8(JWE Protected Header)))
    obj.aad = json_b64encode(obj.protected, 'ascii')

    # compress message if required
    if zip_:
        msg = zip_.compress(obj.payload)
    else:
        msg = obj.payload

    # perform encryption
    enc.encrypt(msg, obj)
    return b'.'.join([
        obj.aad,
        urlsafe_b64encode(recipient.ek),
        urlsafe_b64encode(obj.iv),
        urlsafe_b64encode(obj.ciphertext),
        urlsafe_b64encode(obj.tag)
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
    obj.aad = header_segment

    recipient = Recipient()
    recipient.ek = urlsafe_b64decode(ek_segment)

    obj.iv = urlsafe_b64decode(iv_segment)
    obj.ciphertext = urlsafe_b64decode(ciphertext_segment)
    obj.tag = urlsafe_b64decode(tag_segment)
    obj.add_recipient(recipient)
    return obj


def decrypt_compact(
        obj: EncryptionData,
        private_key,
        registry: JWERegistry,
        sender_key=None) -> EncryptionData:

    if not obj.compact or len(obj.recipients) != 1:
        raise ValueError("Invalid encryption data")

    alg, enc, zip_ = registry.get_algorithms(obj.protected)
    recipient = obj.recipients[0]
    cek = alg.unwrap(enc, obj, recipient, private_key, sender_key)
    obj.cek = cek
    msg = enc.decrypt(obj)
    if zip_:
        obj.payload = zip_.decompress(msg)
    else:
        obj.payload = msg
    return obj
