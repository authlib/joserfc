from unittest import TestCase
from joserfc.jwk import ECKey, OctKey
from joserfc.errors import InvalidExchangeKeyError
from tests.keys import read_key


class TestECKey(TestCase):
    default_key = ECKey.generate_key()

    def test_exchange_derive_key(self):
        key1 = ECKey.generate_key("P-256")
        key2 = ECKey.generate_key("P-384")
        self.assertRaises(InvalidExchangeKeyError, key1.exchange_derive_key, key2)

        key3 = ECKey.generate_key("P-256", private=False)
        self.assertRaises(InvalidExchangeKeyError, key3.exchange_derive_key, key1)

    def run_import_key(self, name):
        public_pem = read_key(f"ec-{name}-public.pem")
        key1 = ECKey.import_key(public_pem)
        self.assertFalse(key1.is_private)

        private_pem = read_key(f"ec-{name}-private.pem")
        key2 = ECKey.import_key(private_pem)
        self.assertTrue(key2.is_private)

        # public key match
        self.assertEqual(
            key2.as_bytes(private=False),
            key1.as_bytes(private=False),
        )

        self.assertNotIn("d", key1.dict_value)
        self.assertIn("d", key2.dict_value)

    def test_import_p256_key(self):
        self.run_import_key("p256")

    def test_import_p384_key(self):
        self.run_import_key("p384")

    def test_import_p512_key(self):
        self.run_import_key("p512")

    def test_import_secp256k1_key(self):
        self.run_import_key("secp256k1")

    def test_generate_key(self):
        self.assertRaises(ValueError, ECKey.generate_key, "Invalid")

        key = ECKey.generate_key(private=True)
        self.assertTrue(key.is_private)
        self.assertIsNone(key.kid)

        key = ECKey.generate_key(private=False)
        self.assertFalse(key.is_private)
        self.assertIsNone(key.private_key)

        key = ECKey.generate_key(auto_kid=True)
        self.assertIsNotNone(key.kid)

    def test_import_from_der_bytes(self):
        value1 = self.default_key.as_der()
        value2 = self.default_key.as_der(private=False)

        key1 = ECKey.import_key(value1)
        key2 = ECKey.import_key(value2)
        self.assertEqual(value1, key1.as_der())
        self.assertEqual(value2, key1.as_der(private=False))
        self.assertEqual(value2, key2.as_der())

    def test_output_with_password(self):
        key = ECKey.import_key(read_key("ec-p256-private.pem"))
        pem = key.as_pem(password="secret")
        self.assertRaises(TypeError, ECKey.import_key, pem)
        key2 = ECKey.import_key(pem, password="secret")
        self.assertEqual(key.as_dict(), key2.as_dict())

    def test_key_eq(self):
        key1 = self.default_key
        key2 = ECKey.import_key(key1.as_dict())
        self.assertEqual(key1, key2)
        key3 = ECKey.generate_key()
        self.assertNotEqual(key1, key3)

    def test_key_eq_with_different_types(self):
        self.assertNotEqual(self.default_key, OctKey.generate_key())
