from unittest import TestCase

from joserfc import jws
from joserfc.jwk import guess_key, import_key, generate_key, thumbprint_uri
from joserfc.jwk import KeySet, OctKey, RSAKey, ECKey, OKPKey
from joserfc.errors import (
    UnsupportedKeyAlgorithmError,
    UnsupportedKeyUseError,
    UnsupportedKeyOperationError,
    InvalidKeyTypeError,
    MissingKeyTypeError,
    InvalidKeyIdError,
)


class Guest:
    def __init__(self):
        self._headers = {"alg": "HS256"}

    def headers(self):
        return self._headers

    def set_kid(self, kid):
        self._headers["kid"] = kid


class TestKeyMethods(TestCase):
    def test_guess_callable_key(self):
        oct_key = OctKey.generate_key(parameters={"kid": "1"})
        rsa_key = RSAKey.generate_key(parameters={"kid": "2"})

        def rsa_key_func(obj):
            return rsa_key

        def key_set_func(obj):
            return KeySet([oct_key, rsa_key])

        key = guess_key(rsa_key_func, Guest())
        self.assertIsInstance(key, RSAKey)

        guest = Guest()
        guest.set_kid("2")
        key = guess_key(key_set_func, guest)
        self.assertIsInstance(key, RSAKey)

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

    def test_thumbprint_uri(self):
        value = thumbprint_uri(
            {
                "kty": "EC",
                "crv": "P-256",
                "x": "jJ6Flys3zK9jUhnOHf6G49Dyp5hah6CNP84-gY-n9eo",
                "y": "nhI6iD5eFXgBTLt_1p3aip-5VbZeMhxeFSpjfEAf7Ww",
            }
        )
        expected = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:w9eYdC6_s_tLQ8lH6PUpc0mddazaqtPgeC2IgWDiqY8"
        self.assertEqual(value, expected)

    def test_find_correct_key_with_use(self):
        key = OctKey.generate_key()
        dict_key = key.as_dict()

        key1 = OctKey.import_key(dict_key, {"use": "enc"})
        key2 = OctKey.import_key(dict_key, {"use": "sig"})
        self.assertEqual(key1.kid, key2.kid)

        key_set = KeySet([key1, key2])
        # pick randomly
        jws.serialize_compact({"alg": "HS256"}, "foo", key_set)
        # get by kid
        jws.serialize_compact({"alg": "HS256", "kid": key2.kid}, "foo", key_set)

        key_set = KeySet([key1, key2, key2])
        # return the first found key
        jws.serialize_compact({"alg": "HS256", "kid": key2.kid}, "foo", key_set)

    def test_find_correct_key_with_alg(self):
        key = OctKey.generate_key()
        dict_key = key.as_dict()

        key1 = OctKey.import_key(dict_key, {"alg": "HS256"})
        key2 = OctKey.import_key(dict_key, {"alg": "dir"})

        self.assertEqual(key1.kid, key2.kid)

        key_set = KeySet([key1, key2])
        # pick randomly
        jws.serialize_compact({"alg": "HS256"}, "foo", key_set)
        # get by kid
        jws.serialize_compact({"alg": "HS256", "kid": key2.kid}, "foo", key_set)
