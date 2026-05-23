from typing import TypedDict, final
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


class JSONSignatureDict(TypedDict, total=False):
    protected: str
    header: Header
    signature: str


@final
class GeneralJSONSerialization(TypedDict):
    payload: str
    signatures: list[JSONSignatureDict]


@final
class FlattenedJSONSerialization(TypedDict, total=False):
    payload: str
    protected: str
    header: Header
    signature: str
