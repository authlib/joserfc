import typing as t
from ..jws import (
    HeaderDict,
    HeaderMember,
    JSONSignature,
    JSONSerialization,
    JWSRegistry as _JWSRegistry,
    serialize_json as _serialize_json,
    deserialize_json as _deserialize_json,
)
from ..jwk import KeyFlexible, guess_key
from ..util import (
    to_bytes,
    to_unicode,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from ..errors import BadSignatureError
from .registry import JWSRegistry


def serialize_json(
        member: HeaderDict,
        payload: t.AnyStr,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[_JWSRegistry] = None) -> JSONSerialization:

    _member = HeaderMember(**member)
    headers = _member.headers()
    if "b64" not in headers:
        return _serialize_json(member, payload, private_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    if headers["b64"] is True:
        return _serialize_json(member, payload, private_key, registry=registry)

    registry.check_header(headers)

    key = guess_key(private_key, _member)
    key.check_use("sig")
    alg = registry.get_alg(headers["alg"])

    if _member.protected:
        protected_segment = json_b64encode(_member.protected)
    else:
        protected_segment = b""

    signing_input = b".".join([protected_segment, to_bytes(payload)])
    signature = urlsafe_b64encode(alg.sign(signing_input, key))

    rv = {
        "payload": to_unicode(payload),
        "signature": to_unicode(signature),
    }
    if protected_segment:
        rv["protected"] = to_unicode(protected_segment)
    if _member.header:
        rv["header"] = _member.header
    return rv


def deserialize_json(
        value: JSONSerialization,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[_JWSRegistry] = None) -> JSONSignature:
    obj = _extract_json(value)
    if obj is None:
        return _deserialize_json(value, public_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    member = obj.members[0]
    headers = member.headers()
    if headers["b64"] is True:
        return _deserialize_json(value, public_key, registry=registry)

    registry.check_header(headers)
    key = guess_key(public_key, member)
    alg = registry.get_alg(headers["alg"])
    signing_input = b".".join([obj.segments["header"], obj.payload])
    sig = urlsafe_b64decode(obj.segments["signature"])
    if not alg.verify(signing_input, sig, key):
        raise BadSignatureError()
    return obj


def _extract_json(value: JSONSerialization):
    if "signatures" in value:
        return None

    if "protected" in value:
        protected_segment = to_bytes(value["protected"])
        protected = json_b64decode(protected_segment)
    else:
        protected_segment = b""
        protected = None

    header = value.get("header")
    member = HeaderMember(protected, header)
    headers = member.headers()
    if "b64" not in headers:
        return None

    payload = to_bytes(value["payload"])
    obj = JSONSignature([member], payload)
    obj.segments = {
        "header": protected_segment,
        "signature": to_bytes(value["signature"]),
    }
    obj.flattened = True
    return obj
