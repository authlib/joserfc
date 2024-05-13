import os
import typing as t
from abc import ABCMeta, abstractmethod
from ..registry import Header, HeaderRegistryDict
from ..errors import InvalidKeyTypeError, InvalidKeyLengthError
from .._keys import Key, ECKey

KeyType = t.TypeVar("KeyType")


class Recipient(t.Generic[KeyType]):
    def __init__(
            self,
            parent: t.Union["CompactEncryption", "GeneralJSONEncryption", "FlattenedJSONEncryption"],
            header: t.Optional[Header] = None,
            recipient_key: t.Optional[KeyType] = None):
        self.__parent = parent
        self.header = header
        self.recipient_key = recipient_key
        self.sender_key: t.Optional[KeyType] = None
        self.encrypted_key: t.Optional[bytes] = None
        self.ephemeral_key: t.Optional[KeyType] = None

    def headers(self) -> Header:
        rv: Header = {}
        rv.update(self.__parent.protected)
        if isinstance(self.__parent, BaseJSONEncryption) and self.__parent.unprotected:
            rv.update(self.__parent.unprotected)
        if self.header:
            rv.update(self.header)
        return rv

    def add_header(self, k: str, v: t.Any):
        if isinstance(self.__parent, CompactEncryption):
            self.__parent.protected.update({k: v})
        elif self.header:
            self.header.update({k: v})
        else:
            self.header = {k: v}

    def set_kid(self, kid: str):
        self.add_header("kid", kid)


class CompactEncryption:
    """An object to represent the JWE Compact Serialization. It is usually returned by
    ``decrypt_compact`` method.
    """
    def __init__(self, protected: Header, plaintext: t.Optional[bytes] = None):
        #: protected header in dict
        self.protected = protected
        #: the plaintext in bytes
        self.plaintext = plaintext
        self.recipient: t.Optional[Recipient] = None
        self.bytes_segments: t.Dict[str, bytes] = {}  # store the decoded segments
        self.base64_segments: t.Dict[str, bytes] = {}  # store the encoded segments

    def headers(self) -> Header:
        return self.protected

    def attach_recipient(self, key: Key, header: t.Optional[Header] = None):
        """Add a recipient to the JWE Compact Serialization. Please add a key that
        comply with the given "alg" value.

        :param key: an instance of a key, e.g. (OctKey, RSAKey, ECKey, and etc)
        :param header: extra header in dict
        """
        recipient = Recipient(self, None, key)
        if header:
            self.protected.update(header)
        self.recipient = recipient

    @property
    def recipients(self) -> t.List[Recipient]:
        if self.recipient is not None:
            return [self.recipient]
        return []


class BaseJSONEncryption(metaclass=ABCMeta):
    #: represents if the object is in flatten syntax
    flattened: t.ClassVar[bool]
    #: protected header in dict
    protected: Header
    #: the plaintext in bytes
    plaintext: t.Optional[bytes]
    #: unprotected header in dict
    unprotected: t.Optional[Header]
    #: an optional additional authenticated data
    aad: t.Optional[bytes]
    #: a list of recipients
    recipients: t.List[Recipient]

    def __init__(
            self,
            protected: Header,
            plaintext: t.Optional[bytes] = None,
            unprotected: t.Optional[Header] = None,
            aad: t.Optional[bytes] = None):
        self.protected = protected
        self.plaintext = plaintext
        self.unprotected = unprotected
        self.aad = aad
        self.recipients = []
        self.bytes_segments: t.Dict[str, bytes] = {}  # store the decoded segments
        self.base64_segments: t.Dict[str, bytes] = {}  # store the encoded segments

    @abstractmethod
    def add_recipient(self, header: t.Optional[Header] = None, key: t.Optional[Key] = None):
        """Add a recipient to the JWE JSON Serialization. Please add a key that
        comply with the "alg" to this recipient.

        :param header: recipient's own (unprotected) header
        :param key: an instance of a key, e.g. (OctKey, RSAKey, ECKey, and etc)
        """


class GeneralJSONEncryption(BaseJSONEncryption):
    """An object to represent the JWE General JSON Serialization. It is used by
    ``encrypt_json``, and it is usually returned by ``decrypt_json`` method.

    To construct an object of ``GeneralJSONEncryption``:

    .. code-block:: python

        protected = {"enc": "A128CBC-HS256"}
        plaintext = b"hello world"
        obj = GeneralJSONEncryption(protected, plaintext)
        # then add each recipient
        obj.add_recipient({"alg": "A128KW"})
    """
    flattened = False

    def add_recipient(self, header: t.Optional[Header] = None, key: t.Optional[Key] = None):
        recipient = Recipient(self, header, key)
        self.recipients.append(recipient)


class FlattenedJSONEncryption(BaseJSONEncryption):
    """An object to represent the JWE Flattened JSON Serialization. It is used by
    ``encrypt_json``, and it is usually returned by ``decrypt_json`` method.

    To construct an object of ``FlattenedJSONEncryption``:

    .. code-block:: python

        protected = {"enc": "A128CBC-HS256"}
        plaintext = b"hello world"
        obj = FlattenedJSONEncryption(protected, plaintext)
        # then add each recipient
        obj.add_recipient({"alg": "A128KW"})
    """
    flattened = True

    def add_recipient(self, header: t.Optional[Header] = None, key: t.Optional[Key] = None):
        self.recipients = [Recipient(self, header, key)]


class JWEEncModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = False
    algorithm_type: t.Literal["JWE"] = "JWE"
    algorithm_location: t.Literal["enc"] = "enc"

    iv_size: int
    cek_size: int

    def generate_cek(self) -> bytes:
        return os.urandom(self.cek_size // 8)

    def generate_iv(self) -> bytes:
        return os.urandom(self.iv_size // 8)

    def check_iv(self, iv: bytes) -> bytes:
        if len(iv) * 8 != self.iv_size:  # pragma: no cover
            raise ValueError('Invalid "iv" size')
        return iv

    @abstractmethod
    def encrypt(self, plaintext: bytes, cek: bytes, iv: bytes, aad: bytes) -> t.Tuple[bytes, bytes]:
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes, tag: bytes, cek: bytes, iv: bytes, aad: bytes) -> bytes:
        pass


class JWEZipModel(object, metaclass=ABCMeta):
    name: str
    description: str
    recommended: bool = True
    algorithm_type: t.Literal["JWE"] = "JWE"
    algorithm_location: t.Literal["zip"] = "zip"

    @abstractmethod
    def compress(self, s: bytes) -> bytes:
        pass

    @abstractmethod
    def decompress(self, s: bytes) -> bytes:
        pass


class KeyManagement:
    name: str
    description: str
    recommended: bool = False
    key_size: t.Optional[int] = None
    key_types: t.List[str]
    algorithm_type: t.Literal["JWE"] = "JWE"
    algorithm_location: t.Literal["alg"] = "alg"
    more_header_registry: HeaderRegistryDict = {}

    @property
    def direct_mode(self) -> bool:
        return self.key_size is None

    def check_key_type(self, key: Key):
        if key.key_type not in self.key_types:
            raise InvalidKeyTypeError()

    def prepare_recipient_header(self, recipient: Recipient):
        raise NotImplementedError()


class JWEDirectEncryption(KeyManagement, metaclass=ABCMeta):
    key_types = ["oct"]

    @abstractmethod
    def compute_cek(self, size: int, recipient: Recipient) -> bytes:
        pass


class JWEKeyEncryption(KeyManagement, metaclass=ABCMeta):
    @property
    def direct_mode(self) -> bool:
        return False

    @abstractmethod
    def encrypt_cek(self, cek: bytes, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def decrypt_cek(self, recipient: Recipient) -> bytes:
        pass


class JWEKeyWrapping(KeyManagement, metaclass=ABCMeta):
    key_size: int
    key_types = ["oct"]

    @property
    def direct_mode(self) -> bool:
        return False

    def check_op_key(self, op_key: bytes):
        if len(op_key) * 8 != self.key_size:
            raise InvalidKeyLengthError(f"A key of size {self.key_size} bits MUST be used")

    @abstractmethod
    def wrap_cek(self, cek: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def unwrap_cek(self, ek: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def encrypt_cek(self, cek: bytes, recipient: Recipient) -> bytes:
        pass

    @abstractmethod
    def decrypt_cek(self, recipient: Recipient) -> bytes:
        pass


class JWEKeyAgreement(KeyManagement, metaclass=ABCMeta):
    key_types = ["EC", "OKP"]
    tag_aware: bool = False
    key_wrapping: t.Optional[JWEKeyWrapping]

    def prepare_ephemeral_key(self, recipient: Recipient[ECKey]):
        recipient_key = recipient.recipient_key
        assert recipient_key is not None
        self.check_key_type(recipient_key)
        if recipient.ephemeral_key is None:
            ephemeral_key = recipient_key.generate_key(recipient_key.curve_name, private=True)
            recipient.ephemeral_key = ephemeral_key
        recipient.add_header("epk", recipient.ephemeral_key.as_dict(private=False))

    @abstractmethod
    def encrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient[ECKey]) -> bytes:
        pass

    @abstractmethod
    def decrypt_agreed_upon_key(self, enc: JWEEncModel, recipient: Recipient[ECKey]) -> bytes:
        pass

    def wrap_cek_with_auk(self, cek: bytes, key: bytes) -> bytes:
        assert self.key_wrapping is not None
        return self.key_wrapping.wrap_cek(cek, key)

    def unwrap_cek_with_auk(self, ek: bytes, key: bytes) -> bytes:
        assert self.key_wrapping is not None
        return self.key_wrapping.unwrap_cek(ek, key)

    def encrypt_agreed_upon_key_with_tag(self, enc: JWEEncModel, recipient: Recipient[ECKey], tag: bytes) -> bytes:
        raise NotImplementedError()

    def decrypt_agreed_upon_key_with_tag(self, enc: JWEEncModel, recipient: Recipient[ECKey], tag: bytes) -> bytes:
        raise NotImplementedError()


JWEAlgModel = t.Union[JWEKeyEncryption, JWEKeyWrapping, JWEKeyAgreement, JWEDirectEncryption]
