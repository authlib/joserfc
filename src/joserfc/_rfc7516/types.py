from typing import Any, NotRequired, TypedDict

__all__ = [
    "JSONRecipientDict",
    "FlattenedJSONSerialization",
    "GeneralJSONSerialization",
]


class JSONRecipientDict(TypedDict, total=False):
    header: dict[str, Any]
    encrypted_key: str


class GeneralJSONSerialization(TypedDict):
    protected: str
    unprotected: NotRequired[dict[str, Any]]
    iv: str
    aad: NotRequired[str]
    ciphertext: str
    tag: str
    recipients: list[JSONRecipientDict]


class FlattenedJSONSerialization(TypedDict):
    protected: str
    unprotected: NotRequired[dict[str, Any]]
    iv: str
    aad: NotRequired[str]
    ciphertext: str
    tag: str
    header: NotRequired[dict[str, Any]]
    encrypted_key: NotRequired[str]
