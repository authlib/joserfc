from .types import EncryptionData, Recipient
from .types import JSONSerialization
from .registry import JWERegistry
from .message import perform_encrypt, perform_decrypt
from ..errors import (
    MissingAlgorithmError,
    MissingEncryptionError,
    DecodeError,
)
from ..util import (
    to_bytes,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def represent_json(obj: EncryptionData) -> JSONSerialization:
    data = {
        'protected': json_b64encode(obj.protected),
        'iv': obj.encoded['iv'],
        'aad': obj.encoded['aad'],
        'ciphertext': obj.encoded['ciphertext'],
        'tag': obj.encoded['tag'],
    }
    if obj.unprotected:
        data['unprotected'] = obj.unprotected

    recipients = []
    for recipient in obj.recipients:
        data = {}
        if recipient.header:
            data['header'] = recipient.header
        if recipient.encrypted_key:
            data['encrypted_key'] = urlsafe_b64encode(recipient.encrypted_key)
        if data:
            recipients.append(data)

    if obj.flatten and len(recipients) == 1:
        data.update(recipients[0])
    else:
        data['recipients'] = recipients
    return data  # type: ignore


def extract_json(data: JSONSerialization) -> EncryptionData:
    protected = json_b64decode(data["protected"])
    unprotected = data.get("unprotected")
    obj = EncryptionData(protected, None, unprotected)
    obj.encoded['iv'] = data['iv']
    obj.encoded['aad'] = data['aad']
    obj.encoded['ciphertext'] = data['ciphertext']
    obj.encoded['tag'] = data['tag']

    if 'recipients' in data:
        obj.flatten = False
        for item in data['recipients']:
            recipient = Recipient(obj, item.get('header'))
            recipient.encrypted_key = urlsafe_b64decode(to_bytes(item['encrypted_key']))
            obj.recipients.append(recipient)
    else:
        obj.flatten = True
        recipient = Recipient(obj, data.get('header'))
        recipient.encrypted_key = urlsafe_b64decode(to_bytes(data['encrypted_key']))
        obj.recipients.append(recipient)
    return obj
