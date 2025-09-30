from __future__ import annotations
import typing as t
from .models import (
    BaseJSONEncryption,
    GeneralJSONEncryption,
    FlattenedJSONEncryption,
    Recipient,
)
from .registry import JWERegistry
from .types import (
    JSONRecipientDict,
    GeneralJSONSerialization,
    FlattenedJSONSerialization,
)
from ..registry import Header
from ..util import (
    to_bytes,
    to_str,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from .._keys import Key


__all__ = [
    "represent_general_json",
    "represent_flattened_json",
    "extract_general_json",
    "extract_flattened_json",
]


def represent_general_json(obj: GeneralJSONEncryption) -> GeneralJSONSerialization:
    data = __represent_json_serialization(obj)
    recipients = []
    for recipient in obj.recipients:
        item: JSONRecipientDict = {}
        if recipient.header:
            item["header"] = recipient.header
        if recipient.encrypted_key:
            item["encrypted_key"] = to_str(urlsafe_b64encode(recipient.encrypted_key))
        recipients.append(item)
    data["recipients"] = recipients
    return data  # type: ignore[no-any-return]


def represent_flattened_json(obj: FlattenedJSONEncryption) -> FlattenedJSONSerialization:
    data = __represent_json_serialization(obj)
    recipient = obj.recipients[0]
    assert recipient is not None
    if recipient.header:
        data["header"] = recipient.header
    if recipient.encrypted_key:
        data["encrypted_key"] = to_str(urlsafe_b64encode(recipient.encrypted_key))
    return data  # type: ignore[no-any-return]


def __represent_json_serialization(obj: BaseJSONEncryption):  # type: ignore[no-untyped-def]
    data: dict[str, t.Union[str, Header, list[Header]]] = {
        "protected": to_str(json_b64encode(obj.protected)),
        "iv": to_str(obj.base64_segments["iv"]),
        "ciphertext": to_str(obj.base64_segments["ciphertext"]),
        "tag": to_str(obj.base64_segments["tag"]),
    }
    if obj.aad:
        data["aad"] = to_str(urlsafe_b64encode(obj.aad))

    if obj.unprotected:
        data["unprotected"] = obj.unprotected
    return data


def extract_general_json(data: GeneralJSONSerialization, registry: JWERegistry) -> GeneralJSONEncryption:
    protected_segment = to_bytes(data["protected"])
    registry.validate_protected_header_size(protected_segment)
    protected = json_b64decode(protected_segment)

    unprotected = data.get("unprotected")
    base64_segments, bytes_segments, aad = __extract_segments(data, registry)

    obj = GeneralJSONEncryption(protected, None, unprotected, aad)
    obj.base64_segments = base64_segments
    obj.bytes_segments = bytes_segments
    for item in data["recipients"]:
        recipient = __extract_recipient(obj, item, registry)
        obj.recipients.append(recipient)
    return obj


def extract_flattened_json(data: FlattenedJSONSerialization, registry: JWERegistry) -> FlattenedJSONEncryption:
    protected_segment = to_bytes(data["protected"])
    registry.validate_protected_header_size(protected_segment)
    protected = json_b64decode(protected_segment)
    unprotected = data.get("unprotected")
    base64_segments, bytes_segments, aad = __extract_segments(data, registry)
    obj = FlattenedJSONEncryption(protected, None, unprotected, aad)
    obj.base64_segments = base64_segments
    obj.bytes_segments = bytes_segments
    recipient = __extract_recipient(obj, data, registry)
    obj.recipients.append(recipient)
    return obj


def __extract_segments(
    data: t.Union[GeneralJSONSerialization, FlattenedJSONSerialization],
    registry: JWERegistry,
) -> tuple[dict[str, bytes], dict[str, bytes], t.Optional[bytes]]:
    base64_segments: dict[str, bytes] = {
        "iv": to_bytes(data["iv"]),
        "ciphertext": to_bytes(data["ciphertext"]),
        "tag": to_bytes(data["tag"]),
    }
    registry.validate_initialization_vector_size(base64_segments["iv"])
    registry.validate_ciphertext_size(base64_segments["ciphertext"])
    registry.validate_auth_tag_size(base64_segments["tag"])
    bytes_segments: dict[str, bytes] = {
        "iv": urlsafe_b64decode(base64_segments["iv"]),
        "ciphertext": urlsafe_b64decode(base64_segments["ciphertext"]),
        "tag": urlsafe_b64decode(base64_segments["tag"]),
    }
    if "aad" in data:
        aad = urlsafe_b64decode(to_bytes(data["aad"]))
    else:
        aad = None
    return base64_segments, bytes_segments, aad


def __extract_recipient(
    obj: FlattenedJSONEncryption | GeneralJSONEncryption,
    data: FlattenedJSONSerialization | JSONRecipientDict,
    registry: JWERegistry,
) -> Recipient[Key]:
    recipient: Recipient[Key] = Recipient(obj, data.get("header"))
    if "encrypted_key" in data:
        ek_segment = to_bytes(data["encrypted_key"])
        registry.validate_encrypted_key_size(ek_segment)
        recipient.encrypted_key = urlsafe_b64decode(ek_segment)
    return recipient
