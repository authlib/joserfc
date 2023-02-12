from typing import List, TypedDict


ProtectedHeader = TypedDict('ProtectedHeader', {
    'alg': str,  # TODO: required
    'jku': str,
    'jwk': str,
    'kid': str,
    'x5u': str,
    'x5c': str,
    'x5t': str,
    'x5t#S256': str,
    'typ': str,
    'cty': str,
    'crit': List[str],
}, total=False)
