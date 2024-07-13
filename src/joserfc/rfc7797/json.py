from __future__ import annotations
import typing as t
from ..rfc7515.json import verify_signature
from ..rfc7515.types import JSONSignatureDict
from ..jws import (
    HeaderDict,
    HeaderMember,
    FlattenedJSONSignature,
    FlattenedJSONSerialization,
    JWSRegistry as _JWSRegistry,
    serialize_json as _serialize_json,
    deserialize_json as _deserialize_json,
)
from ..jwk import Key, KeyFlexible, guess_key
from ..util import (
    to_bytes,
    to_str,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
)
from ..errors import BadSignatureError
from .registry import JWSRegistry


def serialize_json(
        member: HeaderDict,
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: t.Optional[_JWSRegistry] = None) -> FlattenedJSONSerialization:

    _member = HeaderMember(**member)
    headers = _member.headers()
    if "b64" not in headers:
        return _serialize_json(member, payload, private_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    if headers["b64"] is True:
        return _serialize_json(member, payload, private_key, registry=registry)

    registry.check_header(headers)

    key = guess_key(private_key, _member, True)
    key.check_use("sig")
    alg = registry.get_alg(headers["alg"])

    if _member.protected:
        protected_segment = json_b64encode(_member.protected)
    else:
        protected_segment = b""

    signing_input = b".".join([protected_segment, to_bytes(payload)])
    signature = urlsafe_b64encode(alg.sign(signing_input, key))

    rv: FlattenedJSONSerialization = {
        "payload": to_str(payload),
        "signature": to_str(signature),
    }
    if protected_segment:
        rv["protected"] = to_str(protected_segment)
    if _member.header:
        rv["header"] = _member.header
    return rv


def deserialize_json(
        value: FlattenedJSONSerialization,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: t.Optional[_JWSRegistry] = None) -> FlattenedJSONSignature:
    obj = _extract_json(value)
    if obj is None:
        return _deserialize_json(value, public_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    headers = obj.headers()
    if headers["b64"] is True:
        return _deserialize_json(value, public_key, registry=registry)

    payload_segment = obj.segments["payload"]

    def find_key(d: t.Any) -> Key:
        return guess_key(public_key, d)

    assert obj.signature is not None
    if not verify_signature(obj.member, obj.signature, payload_segment, registry, find_key):
        raise BadSignatureError()
    return obj


def _extract_json(value: FlattenedJSONSerialization) -> t.Optional[FlattenedJSONSignature]:
    if "signatures" in value:
        return None

    if "protected" in value:
        protected_segment = to_bytes(value["protected"])
        protected = json_b64decode(protected_segment)
    else:
        protected = None

    header = value.get("header")
    member = HeaderMember(protected, header)
    headers = member.headers()
    if "b64" not in headers:
        return None

    payload = to_bytes(value["payload"])
    obj = FlattenedJSONSignature(member, payload)
    _sig: JSONSignatureDict = {"signature": value["signature"]}
    if "protected" in value:
        _sig["protected"] = value["protected"]
    if "header" in value:
        _sig["header"] = value["header"]
    obj.signature = _sig
    obj.segments = {"payload": payload}
    return obj
