import typing as t

__all__ = ["DictKey", "AnyKey", "KeyParameters"]

#: JSON Web Key in dict
DictKey = t.Dict[str, t.Union[str, t.List[str]]]

#: Key in str, bytes and dict
AnyKey = t.Union[str, bytes, DictKey]

#: extra key parameters for JWK as defined in RFC7517
RFC7517KeyParameters = t.TypedDict("RFC7517KeyParameters", {
    "use": str,
    "key_ops": t.List[str],
    "alg": str,
    "kid": str,
    "x5u": str,
    "x5c": t.List[str],
    "x5t": str,
    "x5t#S256": str,
}, total=False)

class KeyParameters(RFC7517KeyParameters, total=False):
    """
    RFC7517-defined key parameters supplemented by ``joserfc``-specific metadata.
    """
    # Unix timestamp at which the key was created.
    jrfc_created_at: int

    # Boolean indicating whether the key may be used for encryption. If ``True``, the key may
    # not be used for encryption but may still be used for decryption. If ``False``, the key
    # may be used for either operation.
    jrfc_disabled: bool

