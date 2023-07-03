from unittest import TestCase
from joserfc import jwe
from joserfc.errors import InvalidKeyTypeError
from tests.base import load_key


class TestJWEErrors(TestCase):
    def test_dir_with_invalid_key_type(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "dir", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected, b"i", key,
        )

    def test_rsa_with_invalid_key_type(self):
        key = load_key("ec-p256-private.pem")
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.encrypt_compact,
            protected, b"i", key,
        )
