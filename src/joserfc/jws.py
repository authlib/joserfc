from __future__ import annotations
from typing import overload, TypeVar, Any, Dict
from .rfc7515.model import (
    JWSAlgModel,
    HeaderMember,
    CompactSignature,
    GeneralJSONSignature,
    FlattenedJSONSignature,
)
from .rfc7515.registry import (
    JWSRegistry,
    construct_registry,
)
from .rfc7515.compact import (
    sign_compact,
    extract_compact,
    verify_compact,
    detach_compact_content,
)
from .rfc7515.json import (
    sign_general_json,
    sign_flattened_json,
    verify_general_json,
    verify_flattened_json,
    extract_general_json,
    extract_flattened_json,
    detach_json_content,
)
from .rfc7515.types import (
    HeaderDict,
    GeneralJSONSerialization,
    FlattenedJSONSerialization,
)
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8037.jws_eddsa import EdDSA
from .rfc8812 import ES256K
from .errors import BadSignatureError
from .jwk import Key, KeyFlexible, KeySet, guess_key
from .util import to_bytes
from .registry import Header

__all__ = [
    "JWSAlgModel",
    "JWSRegistry",
    "HeaderDict",
    "HeaderMember",
    "CompactSignature",
    "GeneralJSONSignature",
    "FlattenedJSONSignature",
    "GeneralJSONSerialization",
    "FlattenedJSONSerialization",
    "serialize_compact",
    "deserialize_compact",
    "extract_compact",
    "validate_compact",
    "serialize_json",
    "deserialize_json",
    "detach_content",
]


def register_key_set() -> None:
    for _alg in JWS_ALGORITHMS:
        KeySet.algorithm_keys[_alg.name] = [_alg.key_type]
    KeySet.algorithm_keys[EdDSA.name] = [EdDSA.key_type]
    KeySet.algorithm_keys[ES256K.name] = [ES256K.key_type]


# register supported alg models
def register_algorithms() -> None:
    # register alg in RFC7518
    for _alg in JWS_ALGORITHMS:
        JWSRegistry.register(_alg)
    # register alg in RFC8037
    JWSRegistry.register(EdDSA)
    # register alg in RFC8812
    JWSRegistry.register(ES256K)


register_key_set()
register_algorithms()


def serialize_compact(
        protected: Header,
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> str:
    """Generate a JWS Compact Serialization. The JWS Compact Serialization
    represents digitally signed or MACed content as a compact, URL-safe
    string, per Section 7.1.

    .. code-block:: text

        BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload) || '.' ||
        BASE64URL(JWS Signature)

    :param protected: protected header part of the JWS, in dict
    :param payload: payload data of the JWS, in bytes
    :param private_key: a flexible private key to sign the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: JWS in str
    """
    if registry is None:
        registry = construct_registry(algorithms)

    registry.check_header(protected)
    obj = CompactSignature(protected, to_bytes(payload))
    alg: JWSAlgModel = registry.get_alg(protected["alg"])
    key: Key = guess_key(private_key, obj, True)
    key.check_use("sig")
    alg.check_key_type(key)
    key.check_alg(protected["alg"])
    out = sign_compact(obj, alg, key)
    return out.decode("utf-8")


def validate_compact(
        obj: CompactSignature,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> bool:
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    """
    if registry is None:
        registry = construct_registry(algorithms)

    headers = obj.headers()
    registry.check_header(headers)
    key: Key = guess_key(public_key, obj)
    key.check_use("sig")
    alg: JWSAlgModel = registry.get_alg(headers["alg"])
    alg.check_key_type(key)
    return verify_compact(obj, alg, key)


def deserialize_compact(
        value: bytes | str,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> CompactSignature:
    """Extract and validate the JWS Compact Serialization (in string, or bytes)
    with the given key. An JWE Compact Serialization looks like:

    .. code-block:: text
        :caption: line breaks for display purposes only

        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
        .
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
        .
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

    :param value: a string (or bytes) of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: object of the ``CompactSignature``
    """
    obj = extract_compact(to_bytes(value))
    if not validate_compact(obj, public_key, algorithms, registry):
        raise BadSignatureError()
    return obj


@overload
def serialize_json(
        members: list[HeaderDict],
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> GeneralJSONSerialization: ...


@overload
def serialize_json(
        members: HeaderDict,
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> FlattenedJSONSerialization: ...


def serialize_json(
        members: HeaderDict | list[HeaderDict],
        payload: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None,
) -> GeneralJSONSerialization | FlattenedJSONSerialization:
    """Generate a JWS JSON Serialization (in dict). The JWS JSON Serialization
    represents digitally signed or MACed content as a JSON object. This representation
    is neither optimized for compactness nor URL-safe.

    A general JWS JSON Serialization contains:

    payload
        The "payload" member MUST be present and contain the value
        BASE64URL(JWS Payload).

    signatures
        The "signatures" member value MUST be an array of JSON objects.
        Each object represents a signature or MAC over the JWS Payload and
        the JWS Protected Header.

    A flatten JWS JSON Serialization looks like:

    .. code-block:: text

        {
            "payload":"<payload contents>",
            "protected":"<integrity-protected header contents>",
            "header":<non-integrity-protected header contents>,
            "signature":"<signature contents>"
        }
    """
    if registry is None:
        registry = construct_registry(algorithms)

    def find_key(obj: Any) -> Key:
        return guess_key(private_key, obj, True)

    _payload = to_bytes(payload)
    if isinstance(members, list):
        return sign_general_json(members, _payload, registry, find_key)
    else:
        return sign_flattened_json(members, _payload, registry, find_key)


@overload
def deserialize_json(
        value: GeneralJSONSerialization,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> GeneralJSONSignature: ...


@overload
def deserialize_json(
        value: FlattenedJSONSerialization,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None) -> FlattenedJSONSignature: ...


def deserialize_json(
        value: GeneralJSONSerialization | FlattenedJSONSerialization,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWSRegistry | None = None,
) -> GeneralJSONSignature | FlattenedJSONSignature:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: object of the SignatureData
    :raise: ValueError or BadSignatureError
    """
    if registry is None:
        registry = construct_registry(algorithms)

    def find_key(obj: Any) -> Key:
        return guess_key(public_key, obj)

    if "signatures" in value:
        general_obj = extract_general_json(value)
        if not verify_general_json(general_obj, registry, find_key):
            raise BadSignatureError()
        return general_obj
    else:
        flattened_obj = extract_flattened_json(value)
        if not verify_flattened_json(flattened_obj, registry, find_key):
            raise BadSignatureError()
        return flattened_obj


DetachValue = TypeVar("DetachValue", str, Dict[str, Any])


def detach_content(value: DetachValue) -> DetachValue:
    """In some contexts, it is useful to integrity-protect content that is
    not itself contained in a JWS. This method is an implementation of
    https://www.rfc-editor.org/rfc/rfc7515#appendix-F

    It is used to detach the content of the compact and JSON serialization.

    .. code-block:: python

        >>> from joserfc import jws
        >>> from joserfc.jwk import OctKey
        >>> key = OctKey.import_key("secret")
        >>> encoded_text = jws.serialize_compact({"alg": "HS256"}, b"hello", key)
        >>> jws.detach_content(encoded_text)
        'eyJhbGciOiJIUzI1NiJ9..UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

    You can also detach the JSON serialization:

    .. code-block:: python

        >>> obj = jws.serialize_json({"protected": {"alg": "HS256"}}, b"hello", key)
        >>> jws.detach_content(obj)
        {
            'payload': '',
            'signature': 'UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A',
            'protected': 'eyJhbGciOiJIUzI1NiJ9'
        }
    """
    if isinstance(value, str):
        return detach_compact_content(value)
    return detach_json_content(value)
