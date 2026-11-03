from .._rfc7515.json import (
    FindKey,
    check_json_member_headers,
    extract_general_json_parts,
    sign_json_member,
)
from .._rfc7515.json import sign_flattened_json as _sign_flattened_json
from .._rfc7515.json import sign_general_json as _sign_general_json
from .._rfc7515.model import FlattenedJSONSignature, GeneralJSONSignature, HeaderMember
from .._rfc7515.registry import JWSRegistry
from .._rfc7515.types import FlattenedJSONSerialization, GeneralJSONSerialization, JSONSignatureDict
from ..errors import DecodeError, InvalidHeaderValueError, UnsupportedHeaderError
from ..util import json_b64decode, to_bytes, urlsafe_b64decode
from .util import is_rfc7797_enabled


def sign_flattened_json(
    member: HeaderMember,
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> FlattenedJSONSerialization:
    if _is_payload_base64_encoded(member, registry):
        return _sign_flattened_json(member, payload, registry, find_key)
    return sign_rfc7797_json(member, payload, registry, find_key)


def sign_general_json(
    members: list[HeaderMember],
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> GeneralJSONSerialization:
    payload_is_encoded = _validate_general_members(members, registry)
    if payload_is_encoded:
        return _sign_general_json(members, payload, registry, find_key)

    signatures: list[JSONSignatureDict] = [sign_json_member(payload, member, registry, find_key) for member in members]
    return {"payload": payload.decode("utf-8"), "signatures": signatures}


def extract_general_json(value: GeneralJSONSerialization, registry: JWSRegistry) -> GeneralJSONSignature:
    payload_segment, signatures, members = extract_general_json_parts(value, registry)
    payload_is_encoded = _validate_general_members(members, registry)
    if payload_is_encoded:
        try:
            payload = urlsafe_b64decode(payload_segment)
        except (TypeError, ValueError) as error:
            raise DecodeError("Invalid payload") from error
    else:
        payload = payload_segment

    obj = GeneralJSONSignature(members, payload)
    obj.signatures = signatures
    obj.segments = {"payload": payload_segment}
    return obj


def sign_rfc7797_json(
    member: HeaderMember,
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> FlattenedJSONSerialization:
    _is_payload_base64_encoded(member, registry)
    signature = sign_json_member(payload, member, registry, find_key)
    data: FlattenedJSONSerialization = {"payload": payload.decode("utf-8"), **signature}
    return data


def extract_rfc7797_json(value: FlattenedJSONSerialization, registry: JWSRegistry) -> FlattenedJSONSignature:
    if "protected" in value:
        protected_segment = to_bytes(value["protected"])
        registry.validate_header_size(protected_segment)
        protected = json_b64decode(protected_segment)
    else:
        protected = None

    header = value.get("header")
    member = HeaderMember(protected, header)

    payload_segment: bytes = value["payload"].encode("utf-8")
    registry.validate_payload_size(payload_segment)

    payload_is_encoded = _is_payload_base64_encoded(member, registry)
    if payload_is_encoded:
        try:
            payload = urlsafe_b64decode(payload_segment)
        except (TypeError, ValueError) as error:
            raise DecodeError("Invalid payload") from error
    else:
        payload = payload_segment

    obj = FlattenedJSONSignature(member, payload)
    _sig: JSONSignatureDict = {"signature": value["signature"]}
    if "protected" in value:
        _sig["protected"] = value["protected"]
    if "header" in value:
        _sig["header"] = value["header"]
    obj.signature = _sig
    obj.segments = {"payload": payload_segment}
    return obj


def _validate_general_members(members: list[HeaderMember], registry: JWSRegistry) -> bool:
    payload_encodings = [_is_payload_base64_encoded(member, registry) for member in members]
    if payload_encodings and any(encoded != payload_encodings[0] for encoded in payload_encodings[1:]):
        raise InvalidHeaderValueError("'b64' MUST have the same value for all signatures")
    return payload_encodings[0] if payload_encodings else True


def _is_payload_base64_encoded(member: HeaderMember, registry: JWSRegistry) -> bool:
    check_json_member_headers(member, registry)
    if member.header and "b64" in member.header:
        raise UnsupportedHeaderError("'b64' header MUST be protected")
    return not is_rfc7797_enabled(member.protected or {})
