from .types import EncryptionData, Recipient
from .types import JSONSerialization
from ..util import (
    to_bytes,
    to_unicode,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def represent_json(obj: EncryptionData) -> JSONSerialization:
    data = {
        "protected": to_unicode(json_b64encode(obj.protected)),
        "iv": to_unicode(obj.encoded["iv"]),
        "ciphertext": to_unicode(obj.encoded["ciphertext"]),
        "tag": to_unicode(obj.encoded["tag"]),
    }
    if obj.aad:
        data["aad"] = to_unicode(urlsafe_b64encode(obj.aad))

    if obj.unprotected:
        data["unprotected"] = obj.unprotected

    recipients = []
    for recipient in obj.recipients:
        item = {}
        if recipient.header:
            item["header"] = recipient.header
        if recipient.encrypted_key:
            item["encrypted_key"] = to_unicode(urlsafe_b64encode(recipient.encrypted_key))
        if data:
            recipients.append(item)

    if obj.flatten and len(recipients) == 1:
        data.update(recipients[0])
    else:
        data["recipients"] = recipients
    return data  # type: ignore


def extract_json(data: JSONSerialization) -> EncryptionData:
    protected = json_b64decode(data["protected"])
    unprotected = data.get("unprotected")
    obj = EncryptionData(protected, None, unprotected)
    obj.encoded["iv"] = to_bytes(data["iv"])
    obj.encoded["ciphertext"] = to_bytes(data["ciphertext"])
    obj.encoded["tag"] = to_bytes(data["tag"])

    # save in decoded segments
    obj.decoded["iv"] = urlsafe_b64decode(obj.encoded["iv"])
    obj.decoded["ciphertext"] = urlsafe_b64decode(obj.encoded["ciphertext"])
    obj.decoded["tag"] = urlsafe_b64decode(obj.encoded["tag"])

    if "aad" in data:
        obj.aad = urlsafe_b64decode(to_bytes(data["aad"]))

    if "recipients" in data:
        obj.flatten = False
        for item in data["recipients"]:
            recipient = Recipient(obj, item.get("header"))
            recipient.encrypted_key = urlsafe_b64decode(to_bytes(item["encrypted_key"]))
            obj.recipients.append(recipient)
    else:
        obj.flatten = True
        recipient = Recipient(obj, data.get("header"))
        recipient.encrypted_key = urlsafe_b64decode(to_bytes(data["encrypted_key"]))
        obj.recipients.append(recipient)
    return obj
