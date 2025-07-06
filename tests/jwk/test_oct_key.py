from unittest import TestCase
from joserfc.jwk import OctKey
from tests.keys import read_key


class TestOctKey(TestCase):
    def test_import_key_from_str(self):
        key = OctKey.import_key("rfc")
        self.assertEqual(key["k"], "cmZj")
        self.assertEqual(key.raw_value, b"rfc")
        self.assertEqual(dict(key), key.as_dict())

    def test_import_key_from_bytes(self):
        key = OctKey.import_key(b"rfc")
        self.assertEqual(key["k"], "cmZj")
        self.assertEqual(key.raw_value, b"rfc")
        self.assertEqual(dict(key), key.as_dict())

    def test_import_key_from_dict(self):
        # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.3
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": "GawgguFyGrWKav7AX4VKUg",
        }
        key = OctKey.import_key(data)
        self.assertEqual(key.as_dict(), data)

        # with use and key ops
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "use": "sig",
            "key_ops": ["sign", "verify"],
        }
        key = OctKey.import_key(data)
        self.assertEqual(key.as_dict(), data)

    def test_thumbprint_uri(self):
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "use": "sig",
            "key_ops": ["sign", "verify"],
        }
        key = OctKey.import_key(data)
        thumbprint = "k1JnWRfC-5zzmL72vXIuBgTLfVROXBakS4OmGcrMCoc"
        self.assertEqual(key.thumbprint_uri(), f"urn:ietf:params:oauth:jwk-thumbprint:sha-256:{thumbprint}")

    def test_import_missing_k(self):
        data = {
            "kty": "oct",
            "alg": "A128KW",
        }
        self.assertRaises(ValueError, OctKey.import_key, data)

    def test_invalid_typeof_k(self):
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": 123,
        }
        self.assertRaises(ValueError, OctKey.import_key, data)

    def test_mismatch_use_key_ops(self):
        data = {"kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg", "use": "sig", "key_ops": ["wrapKey"]}
        self.assertRaises(ValueError, OctKey.import_key, data)

    def test_invalid_use(self):
        data = {
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "use": "invalid",
        }
        self.assertRaises(ValueError, OctKey.import_key, data)

    def test_invalid_key_ops(self):
        data = {
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "key_ops": ["invalid"],
        }
        self.assertRaises(ValueError, OctKey.import_key, data)

    def test_import_pem_key(self):
        public_pem = read_key("ec-p256-public.pem")
        self.assertWarns(UserWarning, OctKey.import_key, public_pem)

    def test_generate_key(self):
        key = OctKey.generate_key()
        self.assertEqual(len(key.raw_value), 32)
        self.assertIsNone(key.kid)

        key = OctKey.generate_key(None)
        self.assertEqual(len(key.raw_value), 32)
        self.assertIsNone(key.kid)

        self.assertRaises(ValueError, OctKey.generate_key, private=False)
        self.assertRaises(ValueError, OctKey.generate_key, 251)

        key = OctKey.generate_key(auto_kid=True)
        self.assertIsNotNone(key.kid)

    def test_key_eq(self):
        key1 = OctKey.generate_key()
        key2 = OctKey.import_key(key1.as_dict())
        self.assertIsNot(key1, key2)
        self.assertEqual(key1, key2)
        key3 = OctKey.generate_key()
        self.assertNotEqual(key1, key3)
