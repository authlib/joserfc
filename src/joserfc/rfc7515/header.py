from typing import List
from .types import Header

__all__ = ['check_header']

_str_fields = [
    'alg',
    'jku',
    'jwk',
    'kid',
    'x5u',
    'x5t',
    'x5t#S256',
    'typ',
    'cty',
]

_list_str_fields = [
    'x5c',
    'crit',
]


def check_header(header: Header, required: List[str]) -> None:
    """Check if the JWS header contains the required fields, and its field value
    is in valid type.

    :param header: dict of the JWS header
    :param required: a list of required field keys
    :raise: ValueError
    """
    for key in required:
        if key not in header:
            raise ValueError(f'Missing "{key}" in header')

    for key in header:
        if key in _str_fields and not isinstance(header[key], str):
            raise ValueError(f'"{key}" in header must be a str')
        elif key in _list_str_fields:
            values = header[key]
            _is_list_str(key, values)


def _is_list_str(key, values):
    if not isinstance(values, list):
        raise ValueError(f'"{key}" in header must be a list[str]')

    for value in values:
        if not isinstance(value, str):
            raise ValueError(f'"{key}" in header must be a list[str]')
