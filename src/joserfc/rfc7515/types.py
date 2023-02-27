import typing as t
import json
from functools import cached_property
from ..registry import Header

__all__ = [
    'Header',
    'HeaderMember',
    'HeaderDict',
    'SignatureData',
    'JSONSignatureDict',
    'CompleteJSONSerialization',
    'FlattenJSONSerialization',
    'JSONSerialization',
]

SegmentsDict = t.TypedDict('SegmentsDict', {
    'header': bytes,
    'payload': bytes,
    'signature': bytes,
}, total=False)


class HeaderMember:
    def __init__(self, protected: Header, header: t.Optional[Header]=None):
        self.protected = protected
        self.header = header
        self.compact = False

    def headers(self) -> Header:
        rv = {}
        rv.update(self.protected)
        if self.header:
            rv.update(self.header)
        return rv

    def set_kid(self, kid: str):
        if self.compact:
            self.protected['kid'] = kid
        else:
            if self.header is None:
                self.header = {}
            self.header['kid'] = kid


class SignatureData:
    def __init__(self, members: t.List[HeaderMember], payload: bytes):
        self.members = members
        self.payload = payload
        self.signatures: t.List[JSONSignatureDict] = []
        self.compact: bool = False
        self.flatten: bool = False
        self.segments: SegmentsDict = {}

    def headers(self) -> Header:
        if self.compact and len(self.members) == 1:
            return self.members[0].protected
        elif self.flatten and len(self.members) == 1:
            return self.members[0].headers()
        raise ValueError("Only compact or flatten data has .headers() method.")

    @cached_property
    def claims(self) -> t.Dict[str, t.Any]:
        return json.loads(self.payload)


HeaderDict = t.TypedDict('HeaderDict', {
    'protected': Header,
    'header': Header,
}, total=False)


JSONSignatureDict = t.TypedDict('JSONSignatureDict', {
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)


CompleteJSONSerialization = t.TypedDict('CompleteJSONSerialization', {
    'payload': str,
    'signatures': t.List[JSONSignatureDict],
})

FlattenJSONSerialization = t.TypedDict('FlattenJSONSerialization', {
    'payload': str,
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]
