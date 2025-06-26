import typing as t

__all__ = [
    "JSONRecipientDict",
    "FlattenedJSONSerialization",
    "GeneralJSONSerialization",
]


class JSONRecipientDict(t.TypedDict, total=False):
    header: t.Dict[str, t.Any]
    encrypted_key: str


class GeneralJSONSerialization(t.TypedDict, total=False):
    protected: str
    unprotected: t.Dict[str, t.Any]
    iv: str
    aad: str
    ciphertext: str
    tag: str
    recipients: t.List[JSONRecipientDict]


class FlattenedJSONSerialization(t.TypedDict, total=False):
    protected: str
    unprotected: t.Dict[str, t.Any]
    iv: str
    aad: str
    ciphertext: str
    tag: str
    header: t.Dict[str, t.Any]
    encrypted_key: str
