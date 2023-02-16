import typing as t
from .._shared import Header

__all__ = [
    'Header',
    'HeaderMember',
    'Signature',
    'CompleteJSONSerialization',
    'FlattenJSONSerialization',
    'JSONSerialization',
    'CompactProtocol',
]


Signature = t.TypedDict('Signature', {
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

HeaderMember = t.TypedDict('HeaderMember', {
    'protected': Header,
    'header': Header,
}, total=False)

CompleteJSONSerialization = t.TypedDict('CompleteJSONSerialization', {
    'payload': str,
    'signatures': t.List[Signature],
})

FlattenJSONSerialization = t.TypedDict('FlattenJSONSerialization', {
    'payload': str,
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]


class CompactProtocol(t.Protocol):
    def claims(self) -> t.Dict[str, t.Any]:
        ...

    def headers(self) -> Header:
        ...

    def set_kid(self, kid: str):
        ...
