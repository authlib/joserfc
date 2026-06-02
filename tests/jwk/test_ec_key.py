from unittest import TestCase
from cryptography.hazmat.primitives import hashes
from joserfc.jwk import ECKey, OctKey
from joserfc.errors import (
    InvalidExchangeKeyError,
    InvalidKeyTypeError,
    InvalidKeyCurveError,
)
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

    def test_import_from_native_keys(self):
        key = ECKey.generate_key()
        self.assertEqual(key, ECKey.import_key(key.private_key))

    def test_generate_key(self):
        self.assertRaises(InvalidKeyCurveError, ECKey.generate_key, "Invalid")

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

    def test_import_invalid_pem_key(self):
        private_pem = read_key("rsa-openssl-private.pem")
        self.assertRaises(InvalidKeyTypeError, ECKey.import_key, private_pem)

    def test_output_with_password(self):
        key = ECKey.import_key(read_key("ec-p256-private.pem"))
        pem = key.as_pem(private=True, password="secret")
        self.assertRaises(TypeError, ECKey.import_key, pem)
        key2 = ECKey.import_key(pem, password="secret")
        self.assertEqual(key.as_dict(), key2.as_dict())

    def test_key_eq(self):
        key1 = self.default_key
        key2 = ECKey.import_key(key1.as_dict(private=True))
        self.assertEqual(key1, key2)
        key3 = ECKey.generate_key()
        self.assertNotEqual(key1, key3)

    def test_key_eq_with_different_types(self):
        self.assertNotEqual(self.default_key, OctKey.generate_key())

    def test_derive_key_errors(self):
        self.assertRaises(InvalidKeyCurveError, ECKey.derive_key, "secret", "invalid")
        self.assertRaises(ValueError, ECKey.derive_key, "secret", kdf_name="invalid")

    def test_derive_key_with_default_kwargs(self):
        key1 = ECKey.derive_key("ec-secret-key")
        key2 = ECKey.derive_key("ec-secret-key")
        self.assertEqual(key1, key2)

        for crv in ["P-256", "P-384", "P-521", "secp256k1"]:
            key1 = ECKey.derive_key("ec-secret-key", crv)
            key2 = ECKey.derive_key("ec-secret-key", crv)
            self.assertEqual(key1, key2)

        for crv in ["P-256", "P-384", "P-521", "secp256k1"]:
            key1 = ECKey.derive_key("ec-secret-key", crv, kdf_name="PBKDF2")
            key2 = ECKey.derive_key("ec-secret-key", crv, kdf_name="PBKDF2")
            self.assertEqual(key1, key2)

    def test_derive_key_with_new_salt(self):
        curves = ["P-256", "P-384", "P-521", "secp256k1"]
        for crv in curves:
            key1 = ECKey.derive_key("ec-secret-key", crv, kdf_options={"salt": b"salt"})
            key2 = ECKey.derive_key("ec-secret-key", crv, kdf_options={"salt": b"salt"})
            self.assertEqual(key1, key2)

    def test_derive_key_with_different_hash(self):
        key1 = ECKey.derive_key("ec-secret-key", "P-256", kdf_options={"algorithm": hashes.SHA256()})
        key2 = ECKey.derive_key("ec-secret-key", "P-256", kdf_options={"algorithm": hashes.SHA512()})
        self.assertNotEqual(key1, key2)

    def run_verify_full_size(self, curve_name: str, expected_base64_count: int):
        """
        Verifies that the full-size keys (private and public) generated using the specified curve conform to the expected
        Base64-encoded string length for their respective components. The checks involve generating keys that could lead
        to truncated values when encoded and ensuring their lengths match the specified expectation.

        See section: https://datatracker.ietf.org/doc/html/rfc7518#section-6.2

        Parameters:
            curve_name (str): The name of the elliptic curve to use for key generation.
            expected_base64_count (int): The expected length of the Base64-encoded key components (x, y, d).

        Raises:
            AssertionError: Raised if any of the generated private or public key components fail to match the expected lengths.
        """
        private_key = ECKey.generate_key(curve_name)
        # find the number which requires one less byte(octet) than a full padding
        byte_count = (private_key.curve_key_size + 7) // 8
        lower_cap = pow(2, 8 * (byte_count - 1))
        attempts_remaining = 1000000

        # now generate keys until we find a parameter which could be truncated
        while (
            private_key.public_key.public_numbers().x >= lower_cap
            and private_key.public_key.public_numbers().y >= lower_cap
            and private_key.private_key.private_numbers().private_value >= lower_cap
        ):
            private_key = ECKey.generate_key(curve_name)
            attempts_remaining -= 1
            if attempts_remaining == 0:
                raise AssertionError("Failed to find a key parameter that could be truncated")

        output_private = private_key.as_dict(private=True)
        self.assertEqual(expected_base64_count, len(output_private["x"]))
        self.assertEqual(expected_base64_count, len(output_private["y"]))
        self.assertEqual(expected_base64_count, len(output_private["d"]))

        pub_key = ECKey.import_key(private_key.public_key)
        output_public = pub_key.as_dict(private=False)
        self.assertEqual(expected_base64_count, len(output_public["x"]))
        self.assertEqual(expected_base64_count, len(output_public["y"]))

    def test_p256_full_size(self):
        self.run_verify_full_size("P-256", 43)

    def test_p384_full_size(self):
        self.run_verify_full_size("P-384", 64)

    def test_p521_full_size(self):
        self.run_verify_full_size("P-521", 88)
