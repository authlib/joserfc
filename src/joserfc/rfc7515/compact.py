import json
import binascii
from typing import Optional, Dict, Any
from .model import JWSAlgModel
from .types import Header
from ..errors import DecodeError, MissingAlgorithmError
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


class CompactData:
    """The object of a JWS Compact Serialization.

    The Compact data contains:

    - protected header in dict
    - payload in bytes
    - signature in bytes
    """
    def __init__(self, header: Header, payload: bytes,
                 signature: Optional[bytes]=None):
        self.header = header
        self.payload = payload
        self.signature = signature
        self._signing_input = None
        self._claims = None

    @property
    def signing_input(self) -> bytes:
        if self._signing_input:
            return self._signing_input

        protected_segment = json_b64encode(self.header)
        payload_segment = urlsafe_b64encode(self.payload)
        self._signing_input = protected_segment + b'.' + payload_segment
        return self._signing_input

    def headers(self) -> Header:
        """A method to return header value.
        This method is designed for CompactProtocol.
        """
        return self.header

    def set_kid(self, kid: str):
        """A method to update "kid" value in header.
        This method is designed for CompactProtocol.
        """
        self.header['kid'] = kid

    def claims(self) -> Dict[str, Any]:
        """Convert payload from bytes to dict.
        This method is usually used in JWT.
        """
        if self._claims is None:
            # cache it, since the payload won't change
            self._claims = json.loads(self.payload)
        return self._claims

    def sign(self, alg: JWSAlgModel, key) -> bytes:
        """Sign the signature of this compact serialization with the given
        algorithm and key.

        :param alg: a registered algorithm instance
        :param key: a private key
        """
        key.check_use('sig')
        self.signature = urlsafe_b64encode(alg.sign(self.signing_input, key))
        return self.signing_input + b'.' + self.signature

    def verify(self, alg: JWSAlgModel, key) -> bool:
        """Verify the signature of this compact serialization with the given
        algorithm and key.

        :param alg: a registered algorithm instance
        :param key: a public key
        """
        key.check_use('sig')
        sig = urlsafe_b64decode(self.signature)
        return alg.verify(self.signing_input, sig, key)


def extract_compact(value: bytes) -> CompactData:
    """Extract the JWS Compact Serialization from bytes to object.

    :param value: JWS in bytes
    :raise: DecodeError
    """
    parts = value.split(b'.')
    if len(parts) != 3:
        raise ValueError('Invalid JSON Web Signature')

    header_segment, payload_segment, signature = parts
    try:
        header = json_b64decode(header_segment)
        if 'alg' not in header:
            raise MissingAlgorithmError()
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid header')

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid payload')

    obj = CompactData(header, payload, signature)
    obj._signing_input = header_segment + b'.' + payload_segment
    return obj
