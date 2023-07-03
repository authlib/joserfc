import typing as t
from abc import ABCMeta, abstractmethod
from .types import SegmentsDict, JSONSignatureDict
from ..registry import Header


class HeaderMember:
    def __init__(self, protected: t.Optional[Header] = None, header: t.Optional[Header] = None):
        self.protected = protected
        self.header = header

    def headers(self) -> Header:
        rv: Header = {}
        if self.protected:
            rv.update(self.protected)
        if self.header:
            rv.update(self.header)
        return rv

    def set_kid(self, kid: str):
        if self.header is None:
            self.header = {}
        self.header["kid"] = kid


class CompactSignature:
    """JSON Web Signature object for compact mode. This object is used to
    represent the JWS instance.
    """
    def __init__(self, protected: Header, payload: bytes):
        self.protected = protected
        self.payload = payload
        self.segments: SegmentsDict = {}

    def headers(self) -> Header:
        return self.protected

    def set_kid(self, kid: str):
        self.protected["kid"] = kid


class JSONSignature:
    """JSON Web Signature object for JSON mode. This object is used to
    represent the JWS instance.
    """
    def __init__(self, members: t.List[HeaderMember], payload: bytes):
        self.members = members
        self.payload = payload
        self.signatures: t.List[JSONSignatureDict] = []
        self.flattened: bool = False
        self.segments: SegmentsDict = {}

    def headers(self) -> Header:
        if self.flattened and len(self.members) == 1:
            return self.members[0].headers()
        raise ValueError("Only flattened JSON Serialization has .headers() method.")


class JWSAlgModel(object, metaclass=ABCMeta):
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """

    name: str
    description: str
    recommended: bool = False
    algorithm_type = "JWS"
    algorithm_location = "sig"

    @abstractmethod
    def sign(self, msg: bytes, key) -> bytes:
        """Sign the text msg with a private/sign key.

        :param msg: message bytes to be signed
        :param key: private key to sign the message
        :return: bytes
        """
        pass

    @abstractmethod
    def verify(self, msg: bytes, sig: bytes, key) -> bool:
        """Verify the signature of text msg with a public/verify key.

        :param msg: message bytes to be signed
        :param sig: result signature to be compared
        :param key: public key to verify the signature
        :return: boolean
        """
        pass
