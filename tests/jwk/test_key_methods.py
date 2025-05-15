from unittest import TestCase
from joserfc.jws import register_key_set
from joserfc.jwk import guess_key, import_key, generate_key
from joserfc.jwk import KeySet, OctKey, RSAKey, ECKey, OKPKey
from joserfc.errors import (
    UnsupportedKeyAlgorithmError,
    UnsupportedKeyUseError,
    UnsupportedKeyOperationError,
    InvalidKeyTypeError,
    MissingKeyTypeError,
    InvalidKeyIdError,
)

register_key_set()


class Guest:
    def __init__(self):
        self._headers = {}

    def headers(self):
        return self._headers

    def set_kid(self, kid):
        self._headers["kid"] = kid


class TestKeyMethods(TestCase):
    def test_guess_str_key(self):
        self.assertRaises(
            DeprecationWarning,
            guess_key,
            "key",
            Guest(),
        )

    def test_guess_bytes_key(self):
        self.assertRaises(
            DeprecationWarning,
            guess_key,
            b"key",
            Guest(),
        )

    def test_guess_callable_key(self):
        oct_key = OctKey.generate_key(parameters={"kid": "1"})
        rsa_key = RSAKey.generate_key(parameters={"kid": "2"})

        def key_func1(obj):
            return "key"

        def key_func2(obj):
            return rsa_key

        def key_func3(obj):
            return KeySet([oct_key, rsa_key])

        self.assertRaises(
            DeprecationWarning,
            guess_key,
            key_func1,
            Guest(),
        )

        key2 = guess_key(key_func2, Guest())
        self.assertIsInstance(key2, RSAKey)

        guest = Guest()
        guest.set_kid("2")
        key3 = guess_key(key_func3, guest)
        self.assertIsInstance(key3, RSAKey)

    def test_guess_key_set(self):
        key_set = KeySet([OctKey.generate_key(), RSAKey.generate_key()])
        guest = Guest()
        guest._headers["alg"] = "HS256"

        self.assertRaises(InvalidKeyIdError, guess_key, key_set, guest)
        key1 = guess_key(key_set, guest, True)
        self.assertIsInstance(key1, OctKey)
        guess_key(key_set, guest)

        guest = Guest()
        guest._headers["alg"] = "RS256"
        self.assertRaises(InvalidKeyIdError, guess_key, key_set, guest)
        key2 = guess_key(key_set, guest, True)
        self.assertIsInstance(key2, RSAKey)

        guest = Guest()
        guest._headers["alg"] = "ES256"
        self.assertRaises(ValueError, guess_key, key_set, guest, True)

    def test_invalid_key(self):
        self.assertRaises(ValueError, guess_key, {}, Guest())

    def test_import_key(self):
        # test bytes
        key = import_key(b"secret", "oct")
        self.assertIsInstance(key, OctKey)

        # test string
        key = import_key("secret", "oct")
        self.assertIsInstance(key, OctKey)

        # test dict
        data = key.as_dict()
        key = import_key(data)
        self.assertIsInstance(key, OctKey)

        self.assertRaises(InvalidKeyTypeError, import_key, "secret", "invalid")

    def test_generate_key(self):
        key = generate_key("oct")
        self.assertIsInstance(key, OctKey)

        key = generate_key("RSA")
        self.assertIsInstance(key, RSAKey)

        key = generate_key("EC")
        self.assertIsInstance(key, ECKey)

        key = generate_key("OKP")
        self.assertIsInstance(key, OKPKey)

        self.assertRaises(InvalidKeyTypeError, generate_key, "invalid", 8)

    def test_check_use(self):
        key = OctKey.import_key("secret", {"use": "sig"})
        key.check_use("sig")
        self.assertRaises(UnsupportedKeyUseError, key.check_use, "enc")
        self.assertRaises(UnsupportedKeyUseError, key.check_use, "invalid")

    def test_check_alg(self):
        key = OctKey.import_key("secret", {"alg": "HS256"})
        key.check_alg("HS256")
        self.assertRaises(UnsupportedKeyAlgorithmError, key.check_alg, "RS256")

    def test_alg_property(self):
        key = OctKey.import_key("secret")
        self.assertIsNone(key.alg)

        key = OctKey.import_key("secret", {"alg": "HS256"})
        self.assertEqual(key.alg, "HS256")

    def test_check_ops(self):
        key = OctKey.import_key("secret", {"key_ops": ["sign", "verify"]})
        key.check_key_op("sign")
        self.assertRaises(UnsupportedKeyOperationError, key.check_key_op, "wrapKey")
        self.assertRaises(UnsupportedKeyOperationError, key.check_key_op, "invalid")
        key = RSAKey.generate_key(private=False)
        self.assertRaises(UnsupportedKeyOperationError, key.check_key_op, "sign")

    def test_import_without_kty(self):
        self.assertRaises(MissingKeyTypeError, import_key, {})
