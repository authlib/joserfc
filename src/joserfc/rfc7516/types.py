import json
from typing import Optional, List
from functools import cached_property
from ..registry import Header

__all__ = [
    'Header',
    'EncryptionData',
    'Recipient',
]


class Recipient:
    def __init__(self, parent: 'EncryptionData', header: Optional[Header]=None):
        self.parent = parent
        self.header = header
        self.recipient_key = None
        self.encrypted_key: Optional[bytes] = None
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
        self.add_header('kid', kid)


class EncryptionData:
    def __init__(self, protected: Header, payload: Optional[bytes]=None,
                 unprotected: Optional[Header]=None):

        self.protected = protected
        self.payload = payload
        self.unprotected = unprotected
        self.recipients: List[Recipient] = []
        self.cek: Optional[bytes] = None  # content encryption key
        self.plaintext: bytes = b''
        self.encoded = {}  # store the encoded segments
        self.decoded = {}  # store the decoded segments
        self.compact = False
        self.flatten = False

    def add_recipient(self, key, header: Optional[Header]=None):
        recipient = Recipient(self, header)
        recipient.recipient_key = key
        self.recipients.append(recipient)

    @cached_property
    def claims(self):
        return json.loads(self.payload)
