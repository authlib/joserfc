from .models import CompactEncryption, Recipient
from .._keys import Key
from ..errors import (
    MissingAlgorithmError,
    MissingEncryptionError,
    DecodeError,
)
from ..util import (
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def represent_compact(obj: CompactEncryption) -> bytes:
    assert obj.recipient is not None
    encrypted_key = obj.recipient.encrypted_key
    assert encrypted_key is not None
    return b".".join([
        obj.base64_segments["aad"],
        urlsafe_b64encode(encrypted_key),
        obj.base64_segments["iv"],
        obj.base64_segments["ciphertext"],
        obj.base64_segments["tag"],
    ])


def extract_compact(value: bytes) -> CompactEncryption:
    parts = value.split(b".")
    if len(parts) != 5:
        raise ValueError("Invalid JSON Web Encryption")

    header_segment, ek_segment, iv_segment, ciphertext_segment, tag_segment = parts
    try:
        protected = json_b64decode(header_segment)
        if "alg" not in protected:
            raise MissingAlgorithmError()
        if "enc" not in protected:
            raise MissingEncryptionError()
    except (TypeError, ValueError):
        raise DecodeError("Invalid header")

    obj = CompactEncryption(protected)
    obj.base64_segments.update({
        "aad": header_segment,
        "iv": iv_segment,
        "ciphertext": ciphertext_segment,
        "tag": tag_segment,
    })
    obj.bytes_segments.update({
        "iv": urlsafe_b64decode(iv_segment),
        "ciphertext": urlsafe_b64decode(ciphertext_segment),
        "tag": urlsafe_b64decode(tag_segment),
    })
    recipient: Recipient[Key] = Recipient(obj)
    recipient.encrypted_key = urlsafe_b64decode(ek_segment)
    obj.recipient = recipient
    return obj
