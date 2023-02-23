import typing as t
from collections import namedtuple

Header = t.Dict[str, t.Any]


def is_str(key:str, value: str):
    if not isinstance(value, str):
        raise ValueError(f'"{key}" in header must be a str')


def is_url(key:str, value: str):
    is_str(key, value)
    if not value.startswith(('http://', 'https://')):
        raise ValueError(f'"{key}" in header must be a URL')

def is_int(key:str, value: int):
    if not isinstance(value, int):
        raise ValueError(f'"{key}" in header must be an int')


def is_list_str(key, values):
    if not isinstance(values, list):
        raise ValueError(f'"{key}" in header must be a list[str]')

    for value in values:
        if not isinstance(value, str):
            raise ValueError(f'"{key}" in header must be a list[str]')


def is_jwk(key, value):
    if not isinstance(value, dict):
        raise ValueError(f'"{key}" in header must be a dict[str, str]')


def check_crit(header: Header):
    for k in header['crit']:
        if k not in header:
            raise ValueError(f'"{k}" is a critical field')


#: Define header parameters
HeaderParameter = namedtuple('HeaderParameter', ['description', 'required', 'check_value'])

HeaderRegistryDict = t.Dict[str, HeaderParameter]

#: Basic JWS header registry
JWS_HEADER_REGISTRY: HeaderRegistryDict = {
    'alg': HeaderParameter('Algorithm', True, is_str),
    'jku': HeaderParameter('JWK Set URL', False, is_url),
    'jwk': HeaderParameter('JSON Web Key', False, is_jwk),
    'kid': HeaderParameter('Key ID', False, is_str),
    'x5u': HeaderParameter('X.509 URL', False, is_url),
    'x5c': HeaderParameter('X.509 Certificate Chain', False, is_list_str),
    'x5t': HeaderParameter('X.509 Certificate SHA-1 Thumbprint', False, is_str),
    'x5t#S256': HeaderParameter('X.509 Certificate SHA-256 Thumbprint', False, is_str),
    'typ': HeaderParameter('Type', False, is_str),
    'cty': HeaderParameter('Content Type', False, is_str),
    'crit': HeaderParameter('Critical', False, is_list_str),
}


JWE_HEADER_REGISTRY = {
    'enc': HeaderParameter('Encryption Algorithm', True, is_str),
    'zip': HeaderParameter('Compression Algorithm', False, is_str),
    **JWS_HEADER_REGISTRY
}
