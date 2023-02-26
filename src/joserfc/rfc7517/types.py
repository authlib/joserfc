import typing as t

__all__ = ['KeyDict', 'KeyAny', 'KeyOptions', 'KeySetDict']

#: JSON Web Key in dict
KeyDict = t.Dict[str, t.Union[str, t.List[str]]]

#: Key in str, bytes and dict
KeyAny = t.Union[str, bytes, KeyDict]

#: extra options for JWK
KeyOptions = t.TypedDict('KeyOptions', {
    'use': str,
    'key_ops': t.List[str],
    'alg': str,
    'kid': str,
    'x5u': str,
    'x5c': t.List[str],
    'x5t': str,
    'x5t#S256': str,
}, total=False)

#: JWKs in dict
KeySetDict = t.TypedDict('KeySetDict', {
    'keys': t.List[KeyDict],
})
