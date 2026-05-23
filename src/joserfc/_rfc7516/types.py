from typing import Any, TypedDict

__all__ = [
    "JSONRecipientDict",
    "FlattenedJSONSerialization",
    "GeneralJSONSerialization",
]


class JSONRecipientDict(TypedDict, total=False):
    header: dict[str, Any]
    encrypted_key: str


class GeneralJSONSerialization(TypedDict, total=False):
    protected: str
    unprotected: dict[str, Any]
    iv: str
    aad: str
    ciphertext: str
    tag: str
    recipients: list[JSONRecipientDict]


class FlattenedJSONSerialization(TypedDict, total=False):
    protected: str
    unprotected: dict[str, Any]
    iv: str
    aad: str
    ciphertext: str
    tag: str
    header: dict[str, Any]
    encrypted_key: str
