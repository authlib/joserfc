from __future__ import annotations
from typing import overload
from .rfc7516.types import (
    GeneralJSONSerialization,
    FlattenedJSONSerialization,
)
from .rfc7516.models import (
    Recipient,
    CompactEncryption,
    GeneralJSONEncryption,
    FlattenedJSONEncryption,
    JWEEncModel,
    JWEZipModel,
)
from .rfc7516.registry import (
    JWERegistry,
    default_registry,
)
from .rfc7516.message import perform_encrypt, perform_decrypt
from .rfc7516.compact import represent_compact, extract_compact
from .rfc7516.json import (
    represent_general_json,
    represent_flattened_json,
    extract_general_json,
    extract_flattened_json,
)
from .rfc7518.jwe_algs import JWE_ALG_MODELS
from .rfc7518.jwe_encs import JWE_ENC_MODELS
from .rfc7518.jwe_zips import JWE_ZIP_MODELS
from .jwk import Key, KeySet, ECKey, OKPKey, KeyFlexible, guess_key
from .util import to_bytes
from .registry import Header

__all__ = [
    "JWERegistry",
    "JWEEncModel",
    "JWEZipModel",
    "Recipient",
    "CompactEncryption",
    "GeneralJSONEncryption",
    "FlattenedJSONEncryption",
    "encrypt_compact",
    "decrypt_compact",
    "encrypt_json",
    "decrypt_json",
    "default_registry",
]


def register_key_set() -> None:
    for _alg in JWE_ALG_MODELS:
        KeySet.algorithm_keys[_alg.name] = _alg.key_types


def register_algorithms() -> None:
    for _alg in JWE_ALG_MODELS:
        JWERegistry.register(_alg)

    for _enc in JWE_ENC_MODELS:
        JWERegistry.register(_enc)

    for _zip in JWE_ZIP_MODELS:
        JWERegistry.register(_zip)


register_key_set()
register_algorithms()


def encrypt_compact(
        protected: Header,
        plaintext: bytes | str,
        public_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None) -> str:
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

    obj = CompactEncryption(protected, to_bytes(plaintext))
    recipient: Recipient[Key] = Recipient(obj)
    key = guess_key(public_key, recipient, True)
    key.check_use("enc")
    recipient.recipient_key = key
    if sender_key:
        recipient.sender_key = _guess_sender_key(recipient, sender_key, True)
    obj.recipient = recipient
    perform_encrypt(obj, registry)
    out = represent_compact(obj)
    return out.decode("utf-8")


def decrypt_compact(
        value: bytes | str,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None) -> CompactEncryption:
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
    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    recipient = obj.recipient
    assert recipient is not None
    key = guess_key(private_key, recipient)
    key.check_use("enc")
    recipient.recipient_key = key
    if sender_key:
        recipient.sender_key = _guess_sender_key(recipient, sender_key)
    perform_decrypt(obj, registry)
    return obj


@overload
def encrypt_json(
        obj: GeneralJSONEncryption,
        public_key: KeyFlexible | None,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None) -> GeneralJSONSerialization:
    ...


@overload
def encrypt_json(
        obj: FlattenedJSONEncryption,
        public_key: KeyFlexible | None,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None) -> FlattenedJSONSerialization:
    ...


def encrypt_json(
        obj: GeneralJSONEncryption | FlattenedJSONEncryption,
        public_key: KeyFlexible | None,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None
) -> GeneralJSONSerialization | FlattenedJSONSerialization:
    """Generate a JWE JSON Serialization (in dict). The JWE JSON Serialization
    represents encrypted content as a JSON object. This representation is neither
    optimized for compactness nor URL safe.

    When calling this method, developers MUST construct an instance of a
    ``GeneralJSONEncryption`` or ``FlattenedJSONEncryption`` object. Here
    is an example::

        from joserfc.jwe import GeneralJSONEncryption

        protected = {"enc": "A128CBC-HS256"}
        plaintext = b"hello world"
        header = {"jku": "https://server.example.com/keys.jwks"}  # optional shared header
        obj = GeneralJSONEncryption(protected, plaintext, header)
        # add the recipients
        obj.add_recipient({"kid": "alice", "alg": "RSA1_5"})  # not configured a key
        bob_key = OctKey.import_key("bob secret")
        obj.add_recipient({"kid": "bob", "alg": "A128KW"}, bob_key)

    :param obj: an instance of ``GeneralJSONEncryption`` or ``FlattenedJSONEncryption``
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
            recipient.sender_key = _guess_sender_key(recipient, sender_key, True)
        if not recipient.recipient_key:
            assert public_key is not None
            key = guess_key(public_key, recipient, True)
            key.check_use("enc")
            recipient.recipient_key = key

    perform_encrypt(obj, registry)
    if isinstance(obj, GeneralJSONEncryption):
        return represent_general_json(obj)
    return represent_flattened_json(obj)


def decrypt_json(
        data: GeneralJSONSerialization | FlattenedJSONSerialization,
        private_key: KeyFlexible,
        algorithms: list[str] | None = None,
        registry: JWERegistry | None = None,
        sender_key: ECKey | OKPKey | KeySet | None = None
) -> GeneralJSONEncryption | FlattenedJSONEncryption:
    """Decrypt the JWE JSON Serialization (in dict) to a
    ``GeneralJSONEncryption`` or ``FlattenedJSONEncryption`` object.

    :param data: JWE JSON Serialization in dict
    :param private_key: a flexible private key to decrypt the CEK
    :param algorithms: a list of allowed algorithms
    :param registry: a JWERegistry to use
    :param sender_key: only required when using ECDH-1PU
    :return: an instance of ``GeneralJSONEncryption`` or ``FlattenedJSONEncryption``
    """
    if algorithms:
        registry = JWERegistry(algorithms=algorithms)
    elif registry is None:
        registry = default_registry

    if "recipients" in data:
        general_obj = extract_general_json(data)  # type: ignore[arg-type]
        _attach_recipient_keys(general_obj.recipients, private_key, sender_key)
        perform_decrypt(general_obj, registry)
        return general_obj
    else:
        flattened_obj = extract_flattened_json(data)  # type: ignore[arg-type]
        _attach_recipient_keys(flattened_obj.recipients, private_key, sender_key)
        perform_decrypt(flattened_obj, registry)
        return flattened_obj


def _attach_recipient_keys(
        recipients: list[Recipient[Key]],
        private_key: KeyFlexible,
        sender_key: ECKey | OKPKey | KeySet | None = None) -> None:
    for recipient in recipients:
        key = guess_key(private_key, recipient)
        key.check_use("enc")
        recipient.recipient_key = key
        if sender_key:
            recipient.sender_key = _guess_sender_key(recipient, sender_key)


def _guess_sender_key(
        recipient: Recipient[Key],
        key: ECKey | OKPKey | KeySet,
        use_random: bool = False) -> ECKey | OKPKey:
    if isinstance(key, KeySet):
        headers = recipient.headers()
        skid = headers.get('skid')
        if skid:
            return key.get_by_kid(skid)  # type: ignore[return-value]
        if use_random:
            skey = key.pick_random_key(headers["alg"])
            if skey is not None:
                recipient.add_header("skid", skey.kid)
                return skey  # type: ignore[return-value]
        raise ValueError("Invalid key")
    return key
