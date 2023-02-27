from typing import Optional, AnyStr, List, Union
from .rfc7515 import types
from .rfc7515.model import JWSAlgModel
from .rfc7515.registry import (
    JWSRegistry,
    default_registry,
)
from .rfc7515.compact import (
    sign_compact,
    extract_compact,
    verify_compact,
)
from .rfc7515.json import (
    sign_json,
    verify_json,
    extract_json,
)
from .rfc7515.types import (
    Header,
    HeaderMember,
    HeaderDict,
    SignatureData,
    JSONSerialization,
)
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8037.jws_eddsa import EdDSA
from .rfc8812 import ES256K
from .errors import BadSignatureError
from .jwk import Key, KeyFlexible, guess_key
from .util import to_bytes, urlsafe_b64encode

__all__ = [
    'types',
    'JWSAlgModel',
    'JWSRegistry',
    'SignatureData',

    'serialize_compact',
    'deserialize_compact',
    'extract_compact',
    'validate_compact',

    'serialize_json',
    'deserialize_json',
    'extract_json',
    'validate_json',
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
        header: Header,
        payload: bytes,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None) -> bytes:
    """Generate a JWS Compact Serialization. The JWS Compact Serialization
    represents digitally signed or MACed content as a compact, URL-safe
    string, per Section 7.1.

    .. code-block:: text

        BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload) || '.' ||
        BASE64URL(JWS Signature)

    :param header: protected header part of the JWS, in dict
    :param payload: payload data of the JWS, in bytes
    :param key: a flexible private key to sign the signature
    :param registry: a JWSRegistry to use
    :return: JWS in bytes

    .. note:: The returned value is in bytes
    """
    if registry is None:
        registry = default_registry

    registry.check_header(header)
    member = HeaderMember(header)
    obj = SignatureData([member], payload)
    obj.compact = True
    alg: JWSAlgModel = registry.get_alg(header['alg'])
    key: Key = guess_key(key, member)
    return sign_compact(obj, alg, key)


def validate_compact(
        obj: SignatureData,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None):
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param key: a flexible public key to verify the signature
    :param registry: a JWSRegistry to use
    :raise: ValueError or BadSignatureError
    """
    if registry is None:
        registry = default_registry
    member = obj.members[0]
    alg: JWSAlgModel = registry.get_alg(member.protected['alg'])
    key: Key = guess_key(key, member)
    if not verify_compact(obj, alg, key):
        raise BadSignatureError()


def deserialize_compact(
        value: AnyStr,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None) -> SignatureData:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a string (or bytes) of the JWS
    :param key: a flexible public key to verify the signature
    :param registry: a JWSRegistry to use
    :return: object of the JWS Compact Serialization
    """
    obj = extract_compact(to_bytes(value))
    validate_compact(obj, key, registry)
    return obj


def serialize_json(
        members: Union[HeaderDict, List[HeaderDict]],
        payload: bytes,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None) -> JSONSerialization:
    if registry is None:
        registry = default_registry

    if isinstance(members, dict):
        flatten = True
        registry.check_header(members['protected'])
        members = [members]
    else:
        flatten = False
        for member in members:
            registry.check_header(member['protected'])

    members = [HeaderMember(**member) for member in members]
    obj = SignatureData(members, payload)
    obj.segments['payload'] = urlsafe_b64encode(payload)
    obj.flatten = flatten

    find_key = lambda d: guess_key(key, d)
    return sign_json(obj, registry.get_alg, find_key)


def validate_json(
        obj: SignatureData,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None):
    """Validate the JWS JSON Serialization with the given key.
    This method is usually used together with ``extract_json``.

    :param obj: object of the JWS JSON Serialization
    :param key: a flexible public key to verify the signature
    :param registry: a JWSRegistry to use
    :raise: ValueError or BadSignatureError
    """
    if registry is None:
        registry = default_registry
    find_key = lambda d: guess_key(key, d)
    if not verify_json(obj, registry.get_alg, find_key):
        raise BadSignatureError()


def deserialize_json(
        value: JSONSerialization,
        key: KeyFlexible,
        registry: Optional[JWSRegistry]=None) -> SignatureData:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param key: a flexible public key to verify the signature
    :param registry: a JWSRegistry to use
    :return: object of the SignatureData
    """
    obj = extract_json(value)
    validate_json(obj, key, registry)
    return obj
