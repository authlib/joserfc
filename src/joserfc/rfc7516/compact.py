from typing import Optional
from .models import JWEAlgModel, JWEEncModel, JWEZipModel
from .types import Header, EncryptionData, Recipient
from ..util import to_bytes, json_b64encode, urlsafe_b64encode


def encrypt_compact(
        protected: Header,
        payload: bytes,
        public_key,
        alg: JWEAlgModel,
        enc: JWEEncModel,
        zip_: Optional[JWEZipModel]=None,
        sender_key=None) -> bytes:
    obj = EncryptionData(protected, payload)
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
    obj.aad = json_b64encode(protected, 'ascii')

    # compress message if required
    if zip_:
        msg = zip_.compress(to_bytes(payload))
    else:
        msg = to_bytes(payload)

    # perform encryption
    enc.encrypt(msg, obj)
    return b'.'.join([
        obj.aad,
        urlsafe_b64encode(recipient.ek),
        urlsafe_b64encode(obj.iv),
        urlsafe_b64encode(obj.ciphertext),
        urlsafe_b64encode(obj.tag)
    ])
