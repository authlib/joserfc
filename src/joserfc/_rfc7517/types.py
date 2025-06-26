import typing as t

__all__ = ["DictKey", "AnyKey", "KeyParameters"]

#: JSON Web Key in dict
DictKey = t.Dict[str, t.Union[str, t.List[str]]]

#: Key in str, bytes and dict
AnyKey = t.Union[str, bytes, DictKey]

#: extra key parameters for JWK
KeyParameters = t.TypedDict(
    "KeyParameters",
    {
        "use": str,
        "key_ops": t.List[str],
        "alg": str,
        "kid": str,
        "x5u": str,
        "x5c": t.List[str],
        "x5t": str,
        "x5t#S256": str,
    },
    total=False,
)
