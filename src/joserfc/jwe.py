import typing as t
from .rfc7516 import types
from .rfc7516.types import JSONSerialization
from .rfc7516.models import (
    Recipient,
    CompactEncryption,
    JSONEncryption,
    JWEEncModel,
    JWEZipModel,
)
from .rfc7516.registry import (
    JWERegistry,
    default_registry,
)
from .rfc7516.message import perform_encrypt, perform_decrypt
from .rfc7516.compact import represent_compact, extract_compact
from .rfc7516.json import represent_json, extract_json
from .rfc7518.jwe_algs import JWE_ALG_MODELS
from .rfc7518.jwe_encs import JWE_ENC_MODELS
from .rfc7518.jwe_zips import JWE_ZIP_MODELS
from .jwk import CurveKey, KeySet, KeyFlexible, guess_key
from .util import to_bytes
from .registry import Header

__all__ = [
    "types",
    "JWERegistry",
    "JWEEncModel",
    "JWEZipModel",
    "Recipient",
    "CompactEncryption",
    "JSONEncryption",
    "encrypt_compact",
    "decrypt_compact",
    "extract_compact",
    "validate_compact",
    "encrypt_json",
    "decrypt_json",
    "default_registry",
]


def __register():
    for _alg in JWE_ALG_MODELS:
        JWERegistry.register(_alg)

    for _enc in JWE_ENC_MODELS:
        JWERegistry.register(_enc)

    for _zip in JWE_ZIP_MODELS:
        JWERegistry.register(_zip)


__register()


def encrypt_compact(
        protected: Header,
        plaintext: bytes,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[CurveKey] = None) -> bytes:
    """Generate a JWE Compact Serialization. The JWE Compact Serialization represents
    encrypted content as a compact, URL-safe string.  This string is::

        BASE64URL(UTF8(JWE Protected Header)) || '.' ||
        BASE64URL(JWE Encrypted Key) || '.' ||
        BASE64URL(JWE Initialization Vector) || '.' ||
        BASE64URL(JWE Ciphertext) || '.' ||
        BASE64URL(JWE Authentication Tag)

    :param protected: protected header part of the JWE, in dict
    :param plaintext: the content (message) to be encrypted
    :param public_key: a public key used to encrypt the CEK
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: JWE Compact Serialization in bytes
    """

    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    obj = CompactEncryption(protected, plaintext)
    recipient = Recipient(obj)
    key = guess_key(public_key, recipient)
    recipient.recipient_key = key
    recipient.sender_key = sender_key
    obj.recipient = recipient
    perform_encrypt(obj, registry)
    return represent_compact(obj)


def decrypt_compact(
        value: t.AnyStr,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[CurveKey] = None) -> CompactEncryption:
    """Extract and validate the JWE Compact Serialization (in string, or bytes)
    with the given key. An JWE Compact Serialization looks like:

    .. code-block:: text
        :caption: line breaks for display purposes only

        OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe
        ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb
        Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV
        mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8
        1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi
        6UklfCpIMfIjf7iGdXKHzg

    :param value: a string (or bytes) of the JWE Compact Serialization
    :param private_key: a flexible private key to decrypt the serialization
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: object of the ``CompactEncryption``
    """
    obj = extract_compact(to_bytes(value))
    return validate_compact(obj, private_key, algorithms, registry, sender_key)


def validate_compact(
        obj: CompactEncryption,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[CurveKey] = None) -> CompactEncryption:
    """Validate the JWE Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWE Compact Serialization
    :param private_key: a flexible private key to decrypt the serialization
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: object of the ``CompactEncryption``
    """
    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    recipient = obj.recipient
    recipient.recipient_key = guess_key(private_key, recipient)
    recipient.sender_key = sender_key
    return perform_decrypt(obj, registry)


def encrypt_json(
        obj: JSONEncryption,
        public_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[t.Union[CurveKey, KeySet]] = None) -> JSONSerialization:
    """Generate a JWE JSON Serialization (in dict). The JWE JSON Serialization
    represents encrypted content as a JSON object. This representation is neither
    optimized for compactness nor URL safe.

    When calling this method, developers MUST construct an instance of a ``JSONEncryption``
    object. Here is an example::

        from joserfc.jwe import JSONEncryption

        protected = {"enc": "A128CBC-HS256"}
        plaintext = b"hello world"
        header = {"jku": "https://server.example.com/keys.jwks"}  # optional shared header
        obj = JSONEncryption(protected, plaintext, header)
        # add the recipients
        obj.add_recipient(None, {"kid": "alice", "alg": "RSA1_5"})  # not configured a key
        bob_key = OctKey.import_key("bob secret")
        obj.add_recipient(bob_key, {"kid": "bob", "alg": "A128KW"})

    :param obj: an instance of ``JSONEncryption``
    :param public_key: a public key used to encrypt the CEK
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: JWE JSON Serialization in dict
    """

    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        if sender_key and not recipient.sender_key:
            recipient.sender_key = _guess_sender_key(recipient, sender_key)
        if not recipient.recipient_key:
            recipient.recipient_key = guess_key(public_key, recipient)

    perform_encrypt(obj, registry)
    return represent_json(obj)


def decrypt_json(
        data: JSONSerialization,
        private_key: KeyFlexible,
        algorithms: t.Optional[t.List[str]] = None,
        registry: t.Optional[JWERegistry] = None,
        sender_key: t.Optional[t.Union[CurveKey, KeySet]] = None) -> JSONEncryption:
    """Decrypt the JWE JSON Serialization (in dict) to a ``JSONEncryption`` object.

    :param data: JWE JSON Serialization in dict
    :param private_key: a flexible private key to decrypt the CEK
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: an instance of ``JSONEncryption``
    """
    obj = extract_json(data)

    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    for recipient in obj.recipients:
        recipient.recipient_key = guess_key(private_key, recipient)
        if sender_key:
            recipient.sender_key = _guess_sender_key(recipient, sender_key)

    return perform_decrypt(obj, registry)


def _guess_sender_key(recipient, key: t.Union[CurveKey, KeySet]):
    if isinstance(key, KeySet):
        header = recipient.headers()
        skid = header.get('skid')
        if skid:
            return key.get_by_kid(skid)
        return None
    return key
