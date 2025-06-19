from __future__ import annotations
import typing as t
import warnings
from ..jws import (
    HeaderDict,
    FlattenedJSONSignature,
    FlattenedJSONSerialization,
    JWSRegistry as _JWSRegistry,
    serialize_json as _serialize_json,
    deserialize_json as _deserialize_json,
)
from ..jwk import KeyFlexible


def serialize_json(
    member: HeaderDict,
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: list[str] | None = None,
    registry: t.Optional[_JWSRegistry] = None,
) -> FlattenedJSONSerialization:
    warnings.warn(
        "Please use jws.serialize_json directly, as this method will be removed in version 1.4.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _serialize_json(member, payload, private_key, algorithms, registry)


def deserialize_json(
    value: FlattenedJSONSerialization,
    public_key: KeyFlexible,
    algorithms: list[str] | None = None,
    registry: t.Optional[_JWSRegistry] = None,
) -> FlattenedJSONSignature:
    warnings.warn(
        "Please use jws.deserialize_json directly, as this method will be removed in version 1.4.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _deserialize_json(value, public_key, algorithms, registry)
