from __future__ import annotations
from typing import Any, ClassVar
from abc import ABCMeta, abstractmethod
from .types import SegmentsDict, JSONSignatureDict
from ..errors import InvalidKeyTypeError
from ..registry import Header


class HeaderMember:
    """A header member of the JSON signature. It is combined with protected header,
    and unprotected header.
    """
    def __init__(self, protected: Header | None = None, header: Header | None = None):
        #: protected header
        self.protected = protected
        #: unprotected header
        self.header = header

    def headers(self) -> Header:
        rv: Header = {}
        if self.protected:
            rv.update(self.protected)
        if self.header:
            rv.update(self.header)
        return rv

    def set_kid(self, kid: str) -> None:
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

    def set_kid(self, kid: str) -> None:
        self.protected["kid"] = kid


class FlattenedJSONSignature:
    """JSON Signature object that represents a flattened JSON serialization."""

    #: mark it as flattened
    flattened: ClassVar[bool] = True

    def __init__(self, member: HeaderMember, payload: bytes):
        #: the only header member
        self.member = member
        #: payload content
        self.payload = payload
        self.signature: JSONSignatureDict | None = None
        self.segments: SegmentsDict = {}

    @property
    def members(self) -> list[HeaderMember]:
        return [self.member]

    def headers(self) -> Header:
        return self.member.headers()


class GeneralJSONSignature:
    """JSON Signature object that represents a general JSON serialization."""

    #: mark it as not flattened (general)
    flattened: ClassVar[bool] = False

    def __init__(self, members: list[HeaderMember], payload: bytes):
        #: a list of header members
        self.members = members
        #: payload content
        self.payload = payload
        self.signatures: list[JSONSignatureDict] = []
        self.segments: SegmentsDict = {}


class JWSAlgModel(object, metaclass=ABCMeta):
    """Interface for JWS algorithm. JWA specification (RFC7518) SHOULD
    implement the algorithms for JWS with this base implementation.
    """

    name: str
    description: str
    recommended: bool = False
    key_type = "oct"
    algorithm_type = "JWS"
    algorithm_location = "sig"

    def check_key_type(self, key: Any) -> None:
        if key.key_type != self.key_type:
            raise InvalidKeyTypeError(f'Algorithm "{self.name}" requires "{self.key_type}" key')

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        """Sign the text msg with a private/sign key.

        :param msg: message bytes to be signed
        :param key: private key to sign the message
        :return: bytes
        """

    @abstractmethod
    def verify(self, msg: bytes, sig: bytes, key: Any) -> bool:
        """Verify the signature of text msg with a public/verify key.

        :param msg: message bytes to be signed
        :param sig: result signature to be compared
        :param key: public key to verify the signature
        :return: boolean
        """
