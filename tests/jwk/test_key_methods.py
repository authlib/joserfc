from unittest import TestCase
from joserfc.jwk import guess_key, import_key, generate_key
from joserfc.jwk import OctKey


class Guest:
    def __init__(self):
        self._headers = {}

    def headers(self):
        return self._headers

    def set_kid(self, kid):
        self._headers["kid"] = kid


class TestKeyMethods(TestCase):
    def test_guess_str_key(self):
        key = guess_key("key", Guest())
        self.assertIsInstance(key, OctKey)

    def test_guess_bytes_key(self):
        key = guess_key(b"key", Guest())
        self.assertIsInstance(key, OctKey)

    def test_guess_callable_key(self):
        def key_func(obj):
            return OctKey.import_key("key")

        key = guess_key(key_func, Guest())
        self.assertIsInstance(key, OctKey)

    def test_invalid_key(self):
        self.assertRaises(ValueError, guess_key, {}, Guest())

    def test_import_key(self):
        key = import_key("oct", "secret")
        self.assertIsInstance(key, OctKey)
        self.assertRaises(ValueError, import_key, "invalid", "secret")

    def test_generate_key(self):
        key = generate_key("oct", 8)
        self.assertIsInstance(key, OctKey)
        self.assertRaises(ValueError, generate_key, "invalid", 8)
