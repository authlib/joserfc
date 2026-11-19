from unittest import TestCase

from joserfc.errors import InvalidKeyIdError, InvalidKeyTypeError, MissingKeyError
from joserfc.jwk import ECKey, KeySet, OctKey, OKPKey, RSAKey
from tests.keys import read_key

KeySet.algorithm_keys["RS256"] = ["RSA"]


class TestKeySet(TestCase):
    def test_import_empty_key_set(self):
        self.assertRaises(MissingKeyError, KeySet.import_key_set, {"keys": []})

    def test_import_key_set_ignores_unknown_kty(self):
        # RFC 7517 Section 5: a key with an unrecognised "kty" is ignored, not fatal.
        jwks = {
            "keys": [
                {"kty": "unknown", "alg": "X", "kid": "unknown"},
                {"kty": ["RSA"], "alg": "X", "kid": "invalid-list"},
                {"kty": 123, "alg": "X", "kid": "invalid-int"},
                {"kty": "oct", "k": "MDEyMzQ1Njc4OWFiY2RlZg", "kid": "classical"},
            ]
        }
        key_set = KeySet.import_key_set(jwks)
        self.assertEqual(len(key_set.keys), 1)
        self.assertEqual(key_set.keys[0].kid, "classical")

    def test_import_key_set_ignores_malformed_keys(self):
        # RFC 7517 Section 5: an unknown curve, a missing member, invalid
        # base64url and an off-curve point are all reasons to ignore a key.
        ec = ECKey.generate_key("P-256").as_dict(private=False)
        okp = OKPKey.generate_key("Ed25519").as_dict(private=False)
        rsa = RSAKey.generate_key(2048).as_dict(private=False)
        valid = OctKey.import_key("a-valid-secret").as_dict(private=False)
        valid["kid"] = "valid"

        unknown_ec_crv = {**ec, "crv": "P-9999", "kid": "unknown-ec-crv"}
        unknown_okp_crv = {**okp, "crv": "Ed9999", "kid": "unknown-okp-crv"}
        ec_without_x = {key: value for key, value in ec.items() if key != "x"}
        rsa_without_n = {key: value for key, value in rsa.items() if key != "n"}
        rsa_bad_n = {**rsa, "n": "not*base64url", "kid": "bad-rsa-n"}
        off_curve = {**ec, "x": "A" * 43, "kid": "off-curve"}

        jwks = {
            "keys": [
                unknown_ec_crv,
                unknown_okp_crv,
                ec_without_x,
                rsa_without_n,
                rsa_bad_n,
                off_curve,
                valid,
            ]
        }
        key_set = KeySet.import_key_set(jwks)
        self.assertEqual(len(key_set.keys), 1)
        self.assertEqual(key_set.keys[0].kid, "valid")

    def test_import_key_set_all_malformed_raises(self):
        jwks = {"keys": [{"kty": "EC", "crv": "P-256"}]}
        self.assertRaises(MissingKeyError, KeySet.import_key_set, jwks)

    def test_generate_and_import_key_set(self):
        jwks1 = KeySet.generate_key_set("RSA", 2048)
        self.assertEqual(len(jwks1.keys), 4)

        for key in jwks1.keys:
            # we will ensure kid when generating the key set
            self.assertIsNotNone(key.kid)

        jwks1_data = jwks1.as_dict(private=True)
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
        key3 = key_set.pick_random_key()
        self.assertIsNotNone(key3)

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

    def test_get_by_kid_without_kid(self):
        rsa_key = RSAKey.generate_key(2048, private=False, auto_kid=True)
        other_rsa_key = RSAKey.generate_key(2048, {"alg": "RS384"}, private=False, auto_kid=True)
        ec_key = ECKey.generate_key("P-256", private=False, auto_kid=True)
        key_set = KeySet([rsa_key, other_rsa_key, ec_key])

        # only one key can be used with the algorithm
        self.assertIs(key_set.get_by_kid(None, {"alg": "RS256"}), rsa_key)
        self.assertIs(key_set.get_by_kid(None, {"alg": "ES256"}), ec_key)

        # several keys can be used with the algorithm
        self.assertRaises(InvalidKeyIdError, key_set.get_by_kid, None, {"alg": "RS384"})
        self.assertRaises(InvalidKeyIdError, key_set.get_by_kid, None)

        # no key can be used with the algorithm
        self.assertRaises(InvalidKeyIdError, key_set.get_by_kid, None, {"alg": "HS256"})

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
        key_set2 = KeySet([RSAKey.import_key(k.as_dict(private=True)) for k in key_set1])
        self.assertIsNot(key_set1, key_set2)
        self.assertEqual(key_set1, key_set2)

    def test_key_set_eq_with_unrelated_type(self):
        key_set = KeySet.generate_key_set("oct", 8, count=1)
        self.assertFalse(key_set == "foo")
        self.assertNotEqual(key_set, "foo")
