import typing as t


Header = t.Dict[str, t.Any]

Signature = t.TypedDict('Signature', {
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

HeaderMember = t.TypedDict('HeaderMember', {
    'protected': Header,
    'header': Header,
}, total=False)

CompleteJSONSerialization = t.TypedDict('CompleteJSONSerialization', {
    'payload': str,
    'signatures': t.List[Signature],
})

FlattenJSONSerialization = t.TypedDict('FlattenJSONSerialization', {
    'payload': str,
    'protected': str,
    'header': Header,
    'signature': str,
}, total=False)

JSONSerialization = t.Union[CompleteJSONSerialization, FlattenJSONSerialization]


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
