from __future__ import annotations
import typing as t
import re
from ..registry import Header
from ..jwk import KeyFlexible, guess_key
from ..jws import (
    CompactSignature,
    JWSRegistry as _JWSRegistry,
    serialize_compact as _serialize_compact,
    deserialize_compact as _deserialize_compact,
)
from ..util import (
    to_bytes,
    to_str,
    json_b64encode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from ..rfc7515.compact import decode_header
from ..errors import BadSignatureError
from .registry import JWSRegistry


def serialize_compact(
        protected: Header,
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: t.Optional[_JWSRegistry] = None) -> str:

    if "b64" not in protected:
        return _serialize_compact(protected, payload, private_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    if protected["b64"] is True:
        return _serialize_compact(protected, payload, private_key, registry=registry)

    registry.check_header(protected)
    obj = CompactSignature(protected, to_bytes(payload))
    alg = registry.get_alg(protected["alg"])
    key = guess_key(private_key, obj, True)
    key.check_use("sig")

    header_segment = json_b64encode(protected)
    signing_input = header_segment + b"." + obj.payload
    signature = urlsafe_b64encode(alg.sign(signing_input, key))

    # if need to detach payload
    if __is_urlsafe_characters(payload):
        out = signing_input + b"." + signature
    else:
        out = header_segment + b".." + signature
    return out.decode("utf-8")


def deserialize_compact(
        value: bytes | str,
        public_key: KeyFlexible,
        payload: t.Optional[bytes | str] = None,
        algorithms: list[str] | None = None,
        registry: t.Optional[JWSRegistry] = None) -> CompactSignature:
    obj = _extract_compact(to_bytes(value), payload)
    if obj is None:
        return _deserialize_compact(value, public_key, algorithms, registry)

    if registry is None:
        registry = JWSRegistry(algorithms=algorithms)

    if obj is True:
        return _deserialize_compact(value, public_key, registry=registry)

    headers = obj.headers()
    registry.check_header(headers)
    key = guess_key(public_key, obj)
    key.check_use("sig")
    alg = registry.get_alg(headers["alg"])

    signing_input = obj.segments["header"] + b"." + obj.payload
    sig = urlsafe_b64decode(obj.segments["signature"])
    if not alg.verify(signing_input, sig, key):
        raise BadSignatureError()
    assert isinstance(obj, CompactSignature)
    return obj


# https://datatracker.ietf.org/doc/html/rfc7797#section-5.2
# the application MUST ensure that the payload contains only the URL-safe
# characters 'a'-'z', 'A'-'Z', '0'-'9', dash ('-'), underscore ('_'),
# and tilde ('~')
_re_urlsafe = re.compile("^[a-zA-Z0-9-_~]+$")


def __is_urlsafe_characters(s: bytes | str) -> bool:
    return bool(_re_urlsafe.match(to_str(s)))


def _extract_compact(value: bytes, payload: t.Optional[bytes | str] = None) -> t.Any:
    parts = value.split(b".")
    if len(parts) != 3:
        raise ValueError("Invalid JSON Web Signature")

    header_segment, payload_segment, signature_segment = parts
    protected = decode_header(header_segment)

    if "b64" not in protected:
        return None

    if protected["b64"] is True:
        return True

    if payload:
        obj = CompactSignature(protected, to_bytes(payload))
    else:
        obj = CompactSignature(protected, payload_segment)
    obj.segments.update({
        "header": header_segment,
        "payload": payload_segment,
        "signature": signature_segment,
    })
    return obj
