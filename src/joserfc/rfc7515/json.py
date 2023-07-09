import typing as t
import binascii
from .model import JWSAlgModel, HeaderMember, JSONSignature
from .types import (
    HeaderDict,
    JSONSignatureDict,
    JSONSerialization,
    GeneralJSONSerialization,
    FlattenedJSONSerialization,
)
from .registry import JWSRegistry
from ..util import (
    to_bytes,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from ..errors import DecodeError


def construct_json_signature(
        members: t.Union[HeaderDict, t.List[HeaderDict]],
        payload: t.AnyStr,
        registry: JWSRegistry) -> JSONSignature:
    if isinstance(members, dict):
        flattened = True
        __check_member(registry, members)
        members = [members]
    else:
        flattened = False
        for member in members:
            __check_member(registry, member)

    members = [HeaderMember(**member) for member in members]
    payload = to_bytes(payload)
    obj = JSONSignature(members, payload)
    obj.flattened = flattened
    return obj


def __check_member(registry: JWSRegistry, member: HeaderDict):
    header = {}
    if "protected" in member:
        header.update(member["protected"])
    if "header" in member:
        header.update(member["header"])
    registry.check_header(header)


def sign_json(obj: JSONSignature, registry: JWSRegistry, find_key) -> JSONSerialization:
    signatures: t.List[JSONSignatureDict] = []

    payload_segment = obj.segments["payload"]
    for member in obj.members:
        headers = member.headers()
        registry.check_header(headers)
        alg = registry.get_alg(headers["alg"])
        key = find_key(member)
        key.check_use("sig")
        signature = __sign_member(payload_segment, member, alg, key)
        signatures.append(signature)

    rv = {"payload": payload_segment.decode("utf-8")}
    if obj.flattened and len(signatures) == 1:
        rv.update(dict(signatures[0]))
    else:
        rv["signatures"] = signatures

    obj.signatures = signatures
    return rv


def __sign_member(payload_segment, member: HeaderMember, alg: JWSAlgModel, key) -> JSONSignatureDict:
    if member.protected:
        protected_segment = json_b64encode(member.protected)
    else:
        protected_segment = b""
    signing_input = b".".join([protected_segment, payload_segment])
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    rv: JSONSignatureDict = {"signature": signature.decode("utf-8")}
    if member.protected:
        rv["protected"] = protected_segment.decode("utf-8")
    if member.header:
        rv["header"] = member.header
    return rv


def extract_json(value: JSONSerialization) -> JSONSignature:
    """Extract the JWS JSON Serialization from dict to object.

    :param value: JWS in dict
    """
    payload_segment: bytes = value["payload"].encode("utf-8")

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError("Invalid payload")

    if "signatures" in value:
        flattened = False
        value: GeneralJSONSerialization
        signatures: t.List[JSONSignatureDict] = value["signatures"]
    else:
        flattened = True
        value: FlattenedJSONSerialization
        _sig: JSONSignatureDict = {
            "protected": value["protected"],
            "signature": value["signature"],
        }
        if "header" in value:
            _sig["header"] = value["header"]
        signatures = [_sig]

    members = []
    for sig in signatures:
        member = HeaderMember()
        if "protected" in sig:
            protected_segment = sig["protected"]
            member.protected = json_b64decode(protected_segment)
        if "header" in sig:
            member.header = sig["header"]
        members.append(member)

    obj = JSONSignature(members, payload)
    obj.segments.update({"payload": payload_segment})
    obj.flattened = flattened
    obj.signatures = signatures
    return obj


def verify_json(obj: JSONSignature, registry: JWSRegistry, find_key) -> bool:
    """Verify the signature of this JSON serialization with the given
    algorithm and key.

    :param obj: instance of the SignatureData
    :param find_alg: a function to return "alg" model
    :param find_key: a function to return public key
    """
    payload_segment = obj.segments["payload"]
    for index, signature in enumerate(obj.signatures):
        member = obj.members[index]
        headers = member.headers()
        registry.check_header(headers)
        alg = registry.get_alg(headers["alg"])
        key = find_key(member)
        key.check_use("sig")
        if not _verify_signature(signature, payload_segment, alg, key):
            return False
    return True


def _verify_signature(signature: JSONSignatureDict, payload_segment, alg: JWSAlgModel, key) -> bool:
    if "protected" in signature:
        protected_segment = signature["protected"].encode("utf-8")
    else:
        protected_segment = b""
    sig = urlsafe_b64decode(signature["signature"].encode("utf-8"))
    signing_input = b".".join([protected_segment, payload_segment])
    return alg.verify(signing_input, sig, key)


def detach_json_content(value: JSONSerialization) -> JSONSerialization:
    # https://www.rfc-editor.org/rfc/rfc7515#appendix-F
    rv = value.copy()  # don't alter original value
    if "payload" in rv:
        del rv["payload"]
    return rv
