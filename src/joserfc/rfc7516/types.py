from typing import Optional, List
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

class EncryptionData:
    def __init__(self, protected: Header, payload: bytes):
        self.protected = protected
        self.payload = payload
        self.iv = None  # initialization vector
        self.aad = None
        self.cek = None  # ciphertext encrypt key
        self.ciphertext = None
        self.tag = None
        self.recipients: List[Recipient] = []

    def add_recipient(self, recipient: Recipient):
        self.recipients.append(recipient)
