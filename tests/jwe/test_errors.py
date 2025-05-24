from unittest import TestCase
from joserfc import jwe
from joserfc.jwk import OctKey, RSAKey
from joserfc.registry import HeaderParameter
from joserfc.errors import (
    InvalidKeyTypeError,
    InvalidKeyLengthError,
    DecodeError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)
from tests.base import load_key


class TestJWEErrors(TestCase):
    def test_dir_with_invalid_key_type(self):
        key1 = load_key("ec-p256-private.pem")
        protected = {"alg": "dir", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
        )

        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
        )

        protected = {"alg": "ECDH-ES+A128KW", "enc": "A128CBC-HS256"}
        key2 = OctKey.import_key("secret")
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key2,
        )

        protected = {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key1,
            algorithms=["PBES2-HS256+A128KW", "A128CBC-HS256"],
        )

    def test_rsa_with_invalid_key_type(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected,
            b"i",
            key,
        )

    def test_A128KW_unwrap_error(self):
        key1 = OctKey.generate_key(128)
        key2 = OctKey.generate_key(128)
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        value = jwe.encrypt_compact(protected, b"i", key1)
        self.assertRaises(DecodeError, jwe.decrypt_compact, value, key2)

    def test_unsupported_algorithm(self):
        key = OctKey.generate_key(128)
        protected = {"alg": "INVALID", "enc": "A128CBC-HS256"}
        self.assertRaises(UnsupportedAlgorithmError, jwe.encrypt_compact, protected, b"i", key)

        registry = jwe.JWERegistry(algorithms=["A128GCMKW"])
        self.assertRaises(UnsupportedAlgorithmError, jwe.encrypt_compact, protected, b"i", key, registry=registry)

    def test_invalid_key_length(self):
        protected = {"alg": "dir", "enc": "A128CBC-HS256"}
        key = OctKey.import_key("secret")
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", key)
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", key)
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        rsa_key = RSAKey.generate_key(1024)
        self.assertRaises(InvalidKeyLengthError, jwe.encrypt_compact, protected, b"i", rsa_key)

    def test_extra_header(self):
        key = OctKey.generate_key(256)
        protected = {"alg": "dir", "enc": "A128CBC-HS256", "custom": "hi"}
        self.assertRaises(UnsupportedHeaderError, jwe.encrypt_compact, protected, b"i", key)

        registry = jwe.JWERegistry(strict_check_header=False)
        jwe.encrypt_compact(protected, b"i", key, registry=registry)

        registry = jwe.JWERegistry(header_registry={"custom": HeaderParameter("Custom", "str")})
        jwe.encrypt_compact(protected, b"i", key, registry=registry)

    def test_strict_check_header_with_more_header_registry(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "ECDH-ES", "enc": "A128CBC-HS256", "custom": "hi"}
        self.assertRaises(UnsupportedHeaderError, jwe.encrypt_compact, protected, b"i", key)
        registry = jwe.JWERegistry(strict_check_header=False)
        jwe.encrypt_compact(protected, b"i", key, registry=registry)
