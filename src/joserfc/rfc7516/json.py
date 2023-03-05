import binascii
from .types import EncryptionData, Recipient, JSONSerialization
from .registry import JWERegistry
from .message import perform_encrypt, perform_decrypt
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


def represent_json(obj: EncryptionData) -> JSONSerialization:
    rv = {
        'protected': json_b64encode(obj.protected),
        'iv': obj.encoded['iv'],
        'ciphertext': obj.encoded['ciphertext'],
        'tag': obj.encoded['tag'],
    }
    if obj.unprotected:
        rv['unprotected'] = obj.unprotected

    recipients = []
    for recipient in obj.recipients:
        data = {}
        if recipient.header:
            data['header'] = recipient.header
        if recipient.encrypted_key:
            data['encrypted_key'] = urlsafe_b64encode(d.encrypted_key)
        if data:
            recipients.append(data)

    if obj.flatten and len(recipients) == 1:
        rv.update(recipients[0])
    else:
        rv['recipients'] = recipients
    return rv
