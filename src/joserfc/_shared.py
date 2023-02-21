# common shared types
import typing as t

Header = t.Dict[str, t.Any]

default_str_fields = [
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

default_list_str_fields = [
    'x5c',
    'crit',
]


class CompactProtocol(t.Protocol):
    def headers(self) -> Header:
        ...

    def set_kid(self, kid: str):
        ...


def check_header(
        header: Header,
        required: t.List[str],
        str_fields: t.List[str],
        list_str_fields: t.List[str]) -> None:

    for key in required:
        if key not in header:
            raise ValueError(f'Missing "{key}" in header')

    for key in header:
        if key in str_fields and not isinstance(header[key], str):
            raise ValueError(f'"{key}" in header must be a str')
        elif key in list_str_fields:
            values = header[key]
            _is_list_str(key, values)


def _is_list_str(key, values):
    if not isinstance(values, list):
        raise ValueError(f'"{key}" in header must be a list[str]')

    for value in values:
        if not isinstance(value, str):
            raise ValueError(f'"{key}" in header must be a list[str]')
