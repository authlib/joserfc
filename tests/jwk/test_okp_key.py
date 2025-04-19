from unittest import TestCase
from joserfc.jwk import OKPKey
from joserfc.errors import InvalidExchangeKeyError
from tests.keys import read_key


class TestOKPKey(TestCase):
    def test_exchange_derive_key(self):
        key1 = OKPKey.generate_key("Ed448")
        key2 = OKPKey.generate_key("Ed448")
        # only X25519 and X448 can exchange
        self.assertRaises(InvalidExchangeKeyError, key1.exchange_derive_key, key2)

        key3 = OKPKey.generate_key("X25519", private=False)
        key4 = OKPKey.generate_key("X25519")
        # key3 must have private key
        self.assertRaises(InvalidExchangeKeyError, key3.exchange_derive_key, key4)

        key5 = OKPKey.generate_key("X448")
        # curve name doesn't match
        self.assertRaises(InvalidExchangeKeyError, key4.exchange_derive_key, key5)

    def test_generate_keys(self):
        curves = ["Ed25519", "Ed448", "X25519", "X448"]
        for crv in curves:
            key = OKPKey.generate_key(crv)
            self.assertTrue(key.is_private)
            self.assertEqual(key.curve_name, crv)

        public_key = OKPKey.generate_key("Ed25519", private=False)
        self.assertFalse(public_key.is_private)
        self.assertIsNone(public_key.kid)
        self.assertRaises(ValueError, OKPKey.generate_key, "invalid")

        key = OKPKey.generate_key(auto_kid=True)
        self.assertIsNotNone(key.kid)

    def test_import_pem_key(self):
        private_pem = read_key("okp-ed448-private.pem")
        public_pem = read_key("okp-ed448-public.pem")
        private_key: OKPKey = OKPKey.import_key(private_pem)
        public_key: OKPKey = OKPKey.import_key(public_pem)

        self.assertEqual(private_key.as_pem(), private_pem)
        self.assertEqual(private_key.as_pem(private=False), public_pem)
        self.assertEqual(public_key.as_pem(), public_pem)

        self.assertIn("d", private_key.as_dict())
        self.assertNotIn("d", public_key.as_dict())

    def test_properties(self):
        private_pem = read_key("okp-ed448-private.pem")
        public_pem = read_key("okp-ed448-public.pem")
        private_key: OKPKey = OKPKey.import_key(private_pem)
        public_key: OKPKey = OKPKey.import_key(public_pem)

        self.assertTrue(private_key.is_private)
        self.assertFalse(public_key.is_private)

        self.assertEqual(private_key.private_key, private_key.raw_value)
        self.assertEqual(public_key.public_key, public_key.raw_value)
        self.assertIsNone(public_key.private_key)

    def test_import_from_json(self):
        private_key = OKPKey.import_key(read_key("okp-ed25519-private.json"))
        public_key = OKPKey.import_key(read_key("okp-ed25519-public.json"))
        self.assertTrue(private_key.is_private)
        self.assertFalse(public_key.is_private)

    def test_all_as_methods(self):
        private_json = read_key("okp-ed25519-private.json")
        public_json = read_key("okp-ed25519-public.json")
        key: OKPKey = OKPKey.import_key(private_json)

        # as_dict
        data = key.as_dict()
        self.assertIn("d", data)
        self.assertEqual(data, private_json)
        data = key.as_dict(private=False)
        self.assertNotIn("d", data)
        self.assertEqual(data, public_json)

        # as_pem
        data = key.as_pem()
        self.assertIn(b"PRIVATE", data)
        data = key.as_pem(private=False)
        self.assertIn(b"PUBLIC", data)

        # as_der
        data = key.as_der()
        self.assertIsInstance(data, bytes)

    def test_output_with_password(self):
        key = OKPKey.import_key(read_key("okp-ed25519-private.json"))
        pem = key.as_pem(password="secret")
        self.assertRaises(TypeError, OKPKey.import_key, pem)
        key2 = OKPKey.import_key(pem, password="secret")
        self.assertEqual(key.as_pem(), key2.as_pem())

    def test_key_eq(self):
        key1 = OKPKey.generate_key()
        key2 = OKPKey.import_key(key1.as_dict())
        self.assertIsNot(key1, key2)
        self.assertEqual(key1, key2)
        key3 = OKPKey.generate_key()
        self.assertNotEqual(key1, key3)
