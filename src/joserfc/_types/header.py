from typing import Required, List, TypedDict


Header = TypedDict('Header', {
    'alg': str,
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


SHeader = TypedDict('SHeader', {
    'alg': Required[str],
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

EHeader = TypedDict('EHeader', {
    'alg': Required[str],
    'enc': Required[str],
    'zip': str,
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
