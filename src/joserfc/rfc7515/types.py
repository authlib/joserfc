import typing as t


Header = t.Dict[str, t.Any]

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


def check_header(header: Header, required: t.List[str]) -> Header:
    for key in required:
        if key not in header:
            raise ValueError(f'Missing "{key}" in header')

    for key in header:
        if key in _str_fields and not isinstance(header[key], str):
            raise ValueError(f'"{key}" in header must be a str')

    # TODO check crit: List[str]
    return header
