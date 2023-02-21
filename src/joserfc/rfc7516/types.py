import json
from typing import Optional, List, Dict, Any
from .._shared import Header

__all__ = [
    'Header',
    'EncryptionData',
    'Recipient',
]


class Recipient:
    def __init__(self, header: Optional[Header]=None):
        self.header = header
        self.ek = None  # encrypt key
        self.epk = None  # ephemeral_key

    def headers(self) -> Header:
        return self.header

    def set_kid(self, kid: str):
        self.header['kid'] = kid


class EncryptionData:
    def __init__(self, protected: Header, payload: Optional[bytes]=None):
        self.protected = protected
        self.payload = payload
        self.iv = None  # initialization vector
        self.aad = None
        self.cek = None  # ciphertext encrypt key
        self.ciphertext = None
        self.tag = None
        self.recipients: List[Recipient] = []

        self.compact = False
        self.flatten = False

    def add_recipient(self, recipient: Recipient):
        self.recipients.append(recipient)
