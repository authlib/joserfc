from typing import Union
from .rfc7517.keys import Key
from ._types.headers import SHeader, EHeader
from . import jws
from . import jwe


def encode(header: Union[SHeader, EHeader], payload, key: Key) -> str:
    if isinstance(header, EHeader):
        s = jwe.serialize_compact(header, payload, key)
    else:
        s = jws.serialize_compact(header, payload, key)
    return s.decode('utf-8')


def decode(text: str, key: Key):
    pass
