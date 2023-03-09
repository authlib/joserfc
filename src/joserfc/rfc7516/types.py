import json
import typing as t
from functools import cached_property
from ..registry import Header

__all__ = [
    "Header",
    "EncryptionData",
    "Recipient",
    "JSONSerialization",
    "FlattenJSONSerialization",
    "CompleteJSONSerialization",
]


class Recipient:
    def __init__(self, parent: "EncryptionData", header: t.Optional[Header] = None):
        self.parent = parent
        self.header = header
        self.recipient_key = None
        self.encrypted_key: t.Optional[bytes] = None
        self.ephemeral_key = None
        self.segments = {}  # store temporary segments

    def headers(self) -> Header:
        rv = {}
        rv.update(self.parent.protected)
        if not self.parent.compact and self.parent.unprotected:
            rv.update(self.parent.unprotected)
        if self.header:
            rv.update(self.header)
        return rv

    def add_header(self, key: str, value):
        if self.parent.compact:
            self.parent.protected.update({key: value})
        else:
            self.header.update({key: value})

    def set_kid(self, kid: str):
        self.add_header("kid", kid)


class EncryptionData:
    def __init__(
            self,
            protected: Header,
            payload: t.Optional[bytes] = None,
            unprotected: t.Optional[Header] = None):
        self.protected = protected
        self.payload = payload
        self.unprotected = unprotected
        self.recipients: t.List[Recipient] = []
        self.cek: t.Optional[bytes] = None  # content encryption key
        self.plaintext = payload
        self.aad: t.Optional[bytes] = None  # aad for JSON serialization
        self.encoded = {}  # store the encoded segments
        self.decoded = {}  # store the decoded segments
        self.compact = False
        self.flatten = False

    def add_recipient(self, key, header: t.Optional[Header] = None):
        recipient = Recipient(self, header)
        recipient.recipient_key = key
        self.recipients.append(recipient)

    @cached_property
    def claims(self):
        return json.loads(self.payload)


JSONRecipientDict = t.TypedDict("JSONRecipientDict", {
    "header": t.Dict[str, any],
    "encrypted_key": str,
}, total=False)

CompleteJSONSerialization = t.TypedDict("CompleteJSONSerialization", {
    "protected": str,
    "unprotected": t.Dict[str, any],
    "iv": str,
    "aad": str,
    "ciphertext": str,
    "tag": str,
    "recipients": t.List[JSONRecipientDict],
}, total=False)

FlattenJSONSerialization = t.TypedDict("FlattenJSONSerialization", {
    "protected": str,
    "unprotected": t.Dict[str, any],
    "header": t.Dict[str, any],
    "encrypted_key": str,
    "iv": str,
    "aad": str,
    "ciphertext": str,
    "tag": str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]
