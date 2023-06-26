import typing as t
from ..registry import Header

__all__ = [
    "SegmentsDict",
    "HeaderDict",
    "JSONSignatureDict",
    "GeneralJSONSerialization",
    "FlattenedJSONSerialization",
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


GeneralJSONSerialization = t.TypedDict("GeneralJSONSerialization", {
    "payload": str,
    "signatures": t.List[JSONSignatureDict],
})

FlattenedJSONSerialization = t.TypedDict("FlattenedJSONSerialization", {
    "payload": str,
    "protected": str,
    "header": Header,
    "signature": str,
}, total=False)

JSONSerialization = t.Union[GeneralJSONSerialization, FlattenedJSONSerialization]
