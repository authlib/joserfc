import typing as t
from .rfc7515 import types
from .rfc7515.model import (
    JWSAlgModel,
    HeaderMember,
    CompactSignature,
    JSONSignature,
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
    construct_json_signature,
    sign_json,
    verify_json,
    extract_json,
    detach_json_content,
)
from .rfc7515.types import (
    HeaderDict,
    JSONSerialization,
)
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8037.jws_eddsa import EdDSA
from .rfc8812 import ES256K
from .errors import BadSignatureError
from .jwk import Key, KeyFlexible, guess_key
from .util import to_bytes, urlsafe_b64encode
from .registry import Header

__all__ = [
    "types",
    "JWSAlgModel",
    "JWSRegistry",
    "HeaderMember",
    "CompactSignature",
    "JSONSignature",
    "serialize_compact",
    "deserialize_compact",
    "extract_compact",
    "validate_compact",
    "serialize_json",
    "deserialize_json",
    "extract_json",
    "validate_json",
    "detach_content",
]


# register supported alg models
def __register():
    # register alg in RFC7518
    for _alg in JWS_ALGORITHMS:
        JWSRegistry.register(_alg)
    # register alg in RFC8037
    JWSRegistry.register(EdDSA)
    # register alg in RFC8812
    JWSRegistry.register(ES256K)


__register()


def serialize_compact(
        protected: Header,
        payload: t.AnyStr,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None) -> str:
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
    key: Key = guess_key(private_key, obj)
    key.check_use("sig")
    key.check_alg(protected["alg"])
    out = sign_compact(obj, alg, key)
    return out.decode("utf-8")


def validate_compact(
        obj: CompactSignature,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None):
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :raise: ValueError or BadSignatureError
    """
    if registry is None:
        registry = construct_registry(algorithms)

    headers = obj.headers()
    registry.check_header(headers)
    key: Key = guess_key(public_key, obj)
    key.check_use("sig")
    alg: JWSAlgModel = registry.get_alg(headers["alg"])
    if not verify_compact(obj, alg, key):
        raise BadSignatureError()


def deserialize_compact(
        value: t.AnyStr,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None) -> CompactSignature:
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
    validate_compact(obj, public_key, algorithms, registry)
    return obj


def serialize_json(
        members: t.Union[HeaderDict, t.List[HeaderDict]],
        payload: t.AnyStr,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None) -> JSONSerialization:
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

    obj = construct_json_signature(members, payload, registry)
    obj.segments["payload"] = urlsafe_b64encode(obj.payload)
    find_key = lambda d: guess_key(private_key, d)
    return sign_json(obj, registry, find_key)


def validate_json(
        obj: JSONSignature,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None):
    """Validate the JWS JSON Serialization with the given key.
    This method is usually used together with ``extract_json``.

    :param obj: object of the JWS JSON Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :raise: ValueError or BadSignatureError
    """
    if registry is None:
        registry = construct_registry(algorithms)
    find_key = lambda d: guess_key(public_key, d)
    if not verify_json(obj, registry, find_key):
        raise BadSignatureError()


def deserialize_json(
        value: JSONSerialization,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWSRegistry] = None) -> JSONSignature:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a list of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: object of the SignatureData
    """
    obj = extract_json(value)
    validate_json(obj, public_key, algorithms, registry)
    return obj


def detach_content(value: t.Union[str, JSONSerialization]):
    """In some contexts, it is useful to integrity-protect content that is
    not itself contained in a JWS. This method is an implementation of
    https://www.rfc-editor.org/rfc/rfc7515#appendix-F

    It is used to detach the content of the compact and JSON serialization.

    .. code-block:: python

        >>> from joserfc import jws
        >>> encoded_text = jws.serialize_compact({"alg": "HS256"}, b"hello", "secret")
        >>> jws.detach_content(encoded_text)
        'eyJhbGciOiJIUzI1NiJ9..UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

    You can also detach the JSON serialization:

    .. code-block:: python

        >>> obj = jws.serialize_json({"protected": {"alg": "HS256"}}, b"hello", "secret")
        >>> jws.detach_content(obj)
        {'payload': '', 'signature': 'UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A', 'protected': 'eyJhbGciOiJIUzI1NiJ9'}
    """
    if isinstance(value, str):
        return detach_compact_content(value)
    return detach_json_content(value)
