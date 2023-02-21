import typing as t
from .._shared import Header

__all__ = [
    'Header',
    'HeaderMember',
    'HeaderDict',
    'SignatureData',
    'SignatureDict',
    'CompleteJSONSerialization',
    'FlattenJSONSerialization',
    'JSONSerialization',
]


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
        self.signatures: t.List[SignatureDict] = []
        self.payload_segment = None
        self.compact = False
        self.flatten = False


HeaderDict = t.TypedDict('HeaderDict', {
    'protected': Header,
    'header': Header,
}, total=False)


SignatureDict = t.TypedDict('SignatureDict', {
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)


CompleteJSONSerialization = t.TypedDict('CompleteJSONSerialization', {
    'payload': str,
    'signatures': t.List[SignatureDict],
})

FlattenJSONSerialization = t.TypedDict('FlattenJSONSerialization', {
    'payload': str,
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]
