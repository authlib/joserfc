import binascii
from .model import JWSAlgModel, CompactSignature
from ..errors import DecodeError, MissingAlgorithmError
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def sign_compact(obj: CompactSignature, alg: JWSAlgModel, key) -> bytes:
    key.check_use("sig")
    header_segment = json_b64encode(obj.headers())
    payload_segment = urlsafe_b64encode(obj.payload)
    signing_input = header_segment + b"." + payload_segment
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    return signing_input + b"." + signature


def extract_compact(value: bytes) -> CompactSignature:
    """Extract the JWS Compact Serialization from bytes to object.

    :param value: JWS in bytes
    :raise: DecodeError
    """
    parts = value.split(b".")
    if len(parts) != 3:
        raise ValueError("Invalid JSON Web Signature")

    header_segment, payload_segment, signature_segment = parts
    try:
        protected = json_b64decode(header_segment)
        if "alg" not in protected:
            raise MissingAlgorithmError()
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError("Invalid header")

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError("Invalid payload")

    obj = CompactSignature(protected, payload)
    obj.segments.update({
        "header": header_segment,
        "payload": payload_segment,
        "signature": signature_segment,
    })
    return obj


def verify_compact(obj: CompactSignature, alg: JWSAlgModel, key) -> bool:
    key.check_use("sig")
    signing_input = obj.segments["header"] + b"." + obj.segments["payload"]
    sig = urlsafe_b64decode(obj.segments["signature"])
    return alg.verify(signing_input, sig, key)
