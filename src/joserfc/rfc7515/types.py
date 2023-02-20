import typing as t
from .._shared import Header

__all__ = [
    'Header',
    'HeaderMember',
    'Signature',
    'CompleteJSONSerialization',
    'FlattenJSONSerialization',
    'JSONSerialization',
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
