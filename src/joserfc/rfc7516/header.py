from typing import List
from .._shared import (
    Header,
    default_str_fields,
    default_list_str_fields,
    check_header as _check_header,
)


def check_header(header: Header, required: List[str]) -> None:
    """Check if the JWS header contains the required fields, and its field value
    is in valid type.

    :param header: dict of the JWE header
    :param required: a list of required field keys
    :raise: ValueError
    """
    _check_header(header, required, default_str_fields + ['enc', 'zip'], default_list_str_fields)
