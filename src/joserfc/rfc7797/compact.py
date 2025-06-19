from __future__ import annotations
import warnings
import typing as t
from ..registry import Header
from ..jwk import KeyFlexible
from ..jws import (
    CompactSignature,
    JWSRegistry as _JWSRegistry,
    serialize_compact as _serialize_compact,
    deserialize_compact as _deserialize_compact,
)
from .registry import JWSRegistry


def serialize_compact(
    protected: Header,
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: list[str] | None = None,
    registry: t.Optional[_JWSRegistry] = None,
) -> str:
    warnings.warn(
        "Please use jws.serialize_compact directly, as this method will be removed in version 1.4.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _serialize_compact(protected, payload, private_key, algorithms, registry)


def deserialize_compact(
    value: bytes | str,
    public_key: KeyFlexible,
    payload: t.Optional[bytes | str] = None,
    algorithms: list[str] | None = None,
    registry: t.Optional[JWSRegistry] = None,
) -> CompactSignature:
    warnings.warn(
        "Please use jws.deserialize_compact directly, as this method will be removed in version 1.4.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return _deserialize_compact(value, public_key, algorithms, registry, payload)
