from unittest import TestCase

from joserfc.errors import InvalidKeyTypeError, InvalidKeyIdError, MissingKeyError
from joserfc.jwk import KeySet, RSAKey, ECKey, OctKey
from tests.keys import read_key

KeySet.algorithm_keys["RS256"] = ["RSA"]


class TestKeySet(TestCase):
    def test_import_empty_key_set(self):
        self.assertRaises(MissingKeyError, KeySet.import_key_set, {"keys": []})

    def test_generate_and_import_key_set(self):
        jwks1 = KeySet.generate_key_set("RSA", 2048)
        self.assertEqual(len(jwks1.keys), 4)

        for key in jwks1.keys:
            # we will ensure kid when generating the key set
            self.assertIsNotNone(key.kid)

        jwks1_data = jwks1.as_dict()
        self.assertEqual(list(jwks1_data.keys()), ["keys"])
        for d1 in jwks1_data["keys"]:
            self.assertIn("d", d1)

        for d1 in jwks1.as_dict(private=False)["keys"]:
            self.assertNotIn("d", d1)

        jwks2 = KeySet.import_key_set(jwks1_data)
        self.assertEqual(len(jwks2.keys), 4)

    def test_generate_key_set_errors(self):
        self.assertRaises(InvalidKeyTypeError, KeySet.generate_key_set, "NOT_FOUND", 2048)

    def test_initialize_key_set(self):
        keys = []
        pem1 = read_key("rsa-openssl-public.pem")
        keys.append(RSAKey.import_key(pem1))
        pem2 = read_key("ec-p256-private.pem")
        keys.append(ECKey.import_key(pem2))

        jwks = KeySet(keys)
        for d1 in jwks.as_dict(private=False)["keys"]:
            self.assertNotIn("d", d1)

        self.assertRaises(ValueError, jwks.as_dict, private=True)

    def test_random_key(self):
        key_set = KeySet.generate_key_set("oct", 8, count=1)
        key1 = key_set.pick_random_key("INVALID")
        self.assertIsNotNone(key1)
        key2 = key_set.pick_random_key("RS256")
        self.assertIsNone(key2)

    def test_key_set_methods(self):
        key_set = KeySet.generate_key_set("oct", 8)
        jwks = key_set.as_dict(custom="hi")
        self.assertIn("keys", jwks)
        key = jwks["keys"][0]
        self.assertEqual(key["custom"], "hi")

        k1 = key_set.get_by_kid(key["kid"])
        self.assertEqual(k1.kid, key["kid"])
        self.assertRaises(InvalidKeyIdError, key_set.get_by_kid, "invalid")

        key_set = KeySet.generate_key_set("oct", 8, count=1)
        k2 = key_set.get_by_kid()
        self.assertIsInstance(k2, OctKey)

    def test_key_set_bool(self):
        key_set = KeySet([])
        self.assertFalse(key_set)

        key_set = KeySet([OctKey.generate_key()])
        self.assertTrue(key_set)

    def test_key_set_iter(self):
        key_set = KeySet.generate_key_set("RSA", 2048)
        for k in key_set:
            self.assertEqual(k.key_type, "RSA")

    def test_key_eq_with_same_keys(self):
        key_set1 = KeySet.generate_key_set("RSA", 2048)
        key_set2 = KeySet(key_set1.keys)
        self.assertIsNot(key_set1, key_set2)
        self.assertEqual(key_set1, key_set2)

    def test_key_eq_with_new_keys(self):
        key_set1 = KeySet.generate_key_set("RSA", 2048)
        key_set2 = KeySet([RSAKey.import_key(k.as_dict()) for k in key_set1])
        self.assertIsNot(key_set1, key_set2)
        self.assertEqual(key_set1, key_set2)
