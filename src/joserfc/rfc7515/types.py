import typing as t
from ..registry import Header

__all__ = [
    "SegmentsDict",
    "HeaderDict",
    "JSONSignatureDict",
    "CompleteJSONSerialization",
    "FlattenJSONSerialization",
    "JSONSerialization",
]

SegmentsDict = t.TypedDict("SegmentsDict", {
    "header": bytes,
    "payload": bytes,
    "signature": bytes,
}, total=False)

HeaderDict = t.TypedDict("HeaderDict", {
    "protected": Header,
    "header": Header,
}, total=False)


JSONSignatureDict = t.TypedDict("JSONSignatureDict", {
    "protected": str,
    "header": Header,
    "signature": str,
}, total=False)


CompleteJSONSerialization = t.TypedDict("CompleteJSONSerialization", {
    "payload": str,
    "signatures": t.List[JSONSignatureDict],
})

FlattenJSONSerialization = t.TypedDict("FlattenJSONSerialization", {
    "payload": str,
    "protected": str,
    "header": Header,
    "signature": str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]
