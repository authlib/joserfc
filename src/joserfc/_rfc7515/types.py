from typing import NotRequired, TypedDict, final

from ..registry import Header

__all__ = [
    "SegmentsDict",
    "HeaderDict",
    "JSONSignatureDict",
    "GeneralJSONSerialization",
    "FlattenedJSONSerialization",
]


class SegmentsDict(TypedDict, total=False):
    header: bytes
    payload: bytes
    signature: bytes


class HeaderDict(TypedDict, total=False):
    protected: Header
    header: Header


class JSONSignatureDict(TypedDict):
    protected: NotRequired[str]
    header: NotRequired[Header]
    signature: str


@final
class GeneralJSONSerialization(TypedDict):
    payload: str
    signatures: list[JSONSignatureDict]


@final
class FlattenedJSONSerialization(TypedDict):
    payload: str
    protected: NotRequired[str]
    header: NotRequired[Header]
    signature: str
