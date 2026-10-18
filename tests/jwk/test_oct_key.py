from unittest import TestCase
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey
from joserfc.util import urlsafe_b64encode
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from joserfc.errors import SecurityWarning, KeyParameterError
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
        self.assertRaises(KeyParameterError, OctKey.import_key, data)

    def test_invalid_typeof_k(self):
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": 123,
        }
        self.assertRaises(KeyParameterError, OctKey.import_key, data)

    def test_mismatch_use_key_ops(self):
        data = {"kty": "oct", "alg": "A128KW", "k": "GawgguFyGrWKav7AX4VKUg", "use": "sig", "key_ops": ["wrapKey"]}
        self.assertRaises(KeyParameterError, OctKey.import_key, data)

    def test_invalid_use(self):
        data = {
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "use": "invalid",
        }
        self.assertRaises(KeyParameterError, OctKey.import_key, data)

    def test_invalid_key_ops(self):
        data = {
            "kty": "oct",
            "k": "GawgguFyGrWKav7AX4VKUg",
            "key_ops": ["invalid"],
        }
        self.assertRaises(KeyParameterError, OctKey.import_key, data)

    def test_import_asymmetric_public_key_rejected(self):
        keys = (RSAKey.generate_key(), ECKey.generate_key(), OKPKey.generate_key())
        for key in keys:
            formats = [PublicFormat.SubjectPublicKeyInfo]
            if isinstance(key, RSAKey):
                formats.append(PublicFormat.PKCS1)
            for encoding in (Encoding.DER, Encoding.PEM):
                for public_format in formats:
                    raw = key.public_key.public_bytes(encoding, public_format)
                    values = [raw, {"kty": "oct", "k": urlsafe_b64encode(raw).decode("ascii")}]
                    if encoding == Encoding.PEM:
                        values.append(raw.decode("ascii"))
                    for value in values:
                        with self.subTest(key=key.key_type, encoding=encoding, public_format=public_format):
                            self.assertRaisesRegex(ValueError, "Asymmetric public keys", OctKey.import_key, value)

    def test_import_ssh_public_key_rejected(self):
        for filename in ("ssh-rsa-public.pem", "ssh-ecdsa-public.pem", "ssh-ed25519-public.pem"):
            raw = read_key(filename)
            for value in (raw, {"kty": "oct", "k": urlsafe_b64encode(raw).decode("ascii")}):
                with self.subTest(filename=filename):
                    self.assertRaisesRegex(ValueError, "Asymmetric public keys", OctKey.import_key, value)

    def test_import_ambiguous_key_material(self):
        # A DER prefix alone does not make a random symmetric key unsafe.
        raw = b"0" + b"x" * 31
        self.assertEqual(OctKey.import_key(raw).raw_value, raw)
        self.assertEqual(OctKey.import_key({"kty": "oct", "k": urlsafe_b64encode(raw).decode("ascii")}).raw_value, raw)
        self.assertWarns(SecurityWarning, OctKey.import_key, b"-----BEGIN not-a-public-key")
        self.assertWarns(SecurityWarning, OctKey.import_key, b"ssh-rsa not-a-public-key")

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

    def test_generate_key_with_warnings(self):
        self.assertWarns(SecurityWarning, OctKey.generate_key, 16)

    def test_import_key_with_warnings(self):
        self.assertWarns(SecurityWarning, OctKey.import_key, b"rfc")

    def test_import_empty_key_rejected(self):
        # An empty oct key produces a deterministic HMAC digest reproducible
        # by any party, so accepting it would let an attacker forge HS256/
        # HS384/HS512 signatures whenever the application's secret resolves
        # to "" or None (unset env var, missing config, fallback).
        self.assertRaisesRegex(ValueError, "must not be empty", OctKey.import_key, "")
        self.assertRaisesRegex(ValueError, "must not be empty", OctKey.import_key, b"")

    def test_key_eq(self):
        key1 = OctKey.generate_key()
        key2 = OctKey.import_key(key1.as_dict())
        self.assertIsNot(key1, key2)
        self.assertEqual(key1, key2)
        key3 = OctKey.generate_key()
        self.assertNotEqual(key1, key3)
