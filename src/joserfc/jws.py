from typing import Optional, AnyStr, List, Union
from .rfc7515.model import JWSAlgModel
from .rfc7515.registry import (
    register_alg_model,
    get_alg_model,
)
from .rfc7515.compact import (
    CompactData,
    extract_compact,
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
from .rfc7515.header import check_header
from .rfc7518.jws_algs import JWS_ALGORITHMS
from .rfc8037.jws_eddsa import EdDSA
from .rfc8812 import ES256K
from .errors import BadSignatureError
from .jwk import Key, KeyFlexible, guess_key
from .util import to_bytes, urlsafe_b64encode

__all__ = [
    'JWSAlgModel',
    'register_alg_model',
    'SignatureData',

    'CompactData',
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
        register_alg_model(_alg)
    # register alg in RFC8037
    register_alg_model(EdDSA)
    # register alg in RFC8812
    register_alg_model(ES256K)

__register()


def serialize_compact(
        header: Header,
        payload: bytes,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None) -> bytes:
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
    :param allowed_algorithms: allowed "alg" models to use, default to HS256, RS256, ES256
    :return: JWS in bytes

    .. note:: The returned value is in bytes
    """
    check_header(header, ['alg'])
    obj = CompactData(header, payload)
    alg: JWSAlgModel = get_alg_model(header['alg'], allowed_algorithms)
    key: Key = guess_key(key, obj, 'sign')
    return obj.sign(alg, key)


def validate_compact(
        obj: CompactData,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None):
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param key: a flexible public key to verify the signature
    :param allowed_algorithms: allowed "alg" models to use, default to HS256, RS256, ES256
    :raise: ValueError or BadSignatureError
    """
    alg: JWSAlgModel = get_alg_model(obj.header['alg'], allowed_algorithms)
    key: Key = guess_key(key, obj, 'verify')
    if not obj.verify(alg, key):
        raise BadSignatureError()


def deserialize_compact(
        value: AnyStr,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None) -> CompactData:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a string (or bytes) of the JWS
    :param key: a flexible public key to verify the signature
    :param allowed_algorithms: allowed "alg" models to use, default to HS256, RS256, ES256
    :return: object of the JWS Compact Serialization
    """

    obj = extract_compact(to_bytes(value))
    validate_compact(obj, key, allowed_algorithms)
    return obj


def serialize_json(
        members: Union[HeaderDict, List[HeaderDict]],
        payload: bytes,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]] = None) -> JSONSerialization:

    if isinstance(members, dict):
        flatten = True
        _check_member_header(members)
        members = [members]
    else:
        flatten = False
        for member in members:
            _check_member_header(member)

    members = [HeaderMember(**member) for member in members]
    obj = SignatureData(members, payload)
    obj.payload_segment = urlsafe_b64encode(payload)
    obj.flatten = flatten
    find_alg, find_key = _create_find_funcs(key, allowed_algorithms)
    return sign_json(obj, find_alg, find_key)


def validate_json(
        obj: SignatureData,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None):
    """Validate the JWS JSON Serialization with the given key.
    This method is usually used together with ``extract_json``.

    :param obj: object of the JWS JSON Serialization
    :param key: a flexible public key to verify the signature
    :param allowed_algorithms: allowed "alg" models to use, default to HS256, RS256, ES256
    :raise: ValueError or BadSignatureError
    """
    find_alg, find_key = _create_find_funcs(key, allowed_algorithms)
    if not verify_json(obj, find_alg, find_key):
        raise BadSignatureError()


def deserialize_json(
        value: JSONSerialization,
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None) -> SignatureData:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param key: a flexible public key to verify the signature
    :param allowed_algorithms: allowed algorithms to use, default to HS256, RS256, ES256
    :return: object of the SignatureData
    """
    obj = extract_json(value)
    validate_json(obj, key, allowed_algorithms)
    return obj


def _check_member_header(member: HeaderDict):
    check_header(member['protected'], ['alg'])
    if 'header' in member:
        check_header(member['header'], [])


def _create_find_funcs(
        key: KeyFlexible,
        allowed_algorithms: Optional[List[str]]=None):
    _find_alg = lambda alg: get_alg_model(alg, allowed_algorithms)
    _find_key = lambda d, operation: guess_key(key, d, operation)
    return _find_alg, _find_key
