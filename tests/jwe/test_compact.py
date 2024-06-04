from unittest import TestCase
from joserfc.jwe import JWERegistry, encrypt_compact, decrypt_compact, CompactEncryption
from joserfc.jwk import RSAKey, ECKey, OctKey, OKPKey, KeySet
from joserfc.rfc7518.jwe_encs import JWE_ENC_MODELS
from joserfc.errors import (
    InvalidKeyLengthError,
    MissingAlgorithmError,
    MissingEncryptionError,
    DecodeError,
)
from joserfc.util import json_b64encode
from tests.base import load_key


class TestJWECompact(TestCase):
    def run_case(self, alg: str, enc: str, private_key, public_key):
        protected = {"alg": alg, "enc": enc}
        payload = b'hello'
        result = encrypt_compact(
            protected, payload, public_key,
            algorithms=[alg, enc],
        )
        self.assertEqual(result.count('.'), 4)

        obj = decrypt_compact(
            result, private_key,
            algorithms=[alg, enc],
        )
        self.assertEqual(obj.plaintext, payload)

    def run_cases(self, names, private_key, public_key):
        for alg in names:
            for enc in JWE_ENC_MODELS:
                self.run_case(alg, enc.name, private_key, public_key)

    def test_RSA_alg(self):
        private_key: RSAKey = load_key('rsa-openssl-private.pem')
        public_key: RSAKey = load_key('rsa-openssl-public.pem')
        algs = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256']
        self.run_cases(algs, private_key, public_key)

        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        value = encrypt_compact(protected, "i", private_key)
        key2 = RSAKey.generate_key()
        self.assertRaises(
            DecodeError,
            decrypt_compact,
            value, key2
        )

    def test_ECDH_ES_with_EC_key(self):
        algs = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
        for size in [256, 384, 512]:
            private_key: ECKey = load_key(f'ec-p{size}-private.pem')
            public_key: ECKey = load_key(f'ec-p{size}-public.pem')
            self.run_cases(algs, private_key, public_key)

        key1 = ECKey.generate_key("P-256")
        key2 = ECKey.generate_key("P-256")
        key3 = ECKey.generate_key("P-521")
        for alg in ["ECDH-ES", "ECDH-ES+A128KW"]:
            for enc in ["A128CBC-HS256", "A128GCM"]:
                protected = {"alg": alg, "enc": enc}
                value = encrypt_compact(protected, "i", key1)
                self.assertRaises(
                    DecodeError,
                    decrypt_compact,
                    value, key2,
                )
                self.assertRaises(
                    DecodeError,
                    decrypt_compact,
                    value, key3,
                )

    def test_ECDH_ES_with_OKP_key(self):
        key1 = OKPKey.generate_key("X25519")
        key2 = OKPKey.generate_key("X448")
        for alg in ['ECDH-ES', 'ECDH-ES+A128KW']:
            for enc in ["A128CBC-HS256", "A128GCM"]:
                protected = {"alg": alg, "enc": enc}
                value = encrypt_compact(protected, "i", key1)
                obj = decrypt_compact(value, key1)
                self.assertEqual(obj.protected, protected)
                self.assertRaises(
                    DecodeError,
                    decrypt_compact,
                    value, key2,
                )

                value = encrypt_compact(protected, "i", key2)
                obj = decrypt_compact(value, key2)
                self.assertEqual(obj.protected, protected)
                self.assertRaises(
                    DecodeError,
                    decrypt_compact,
                    value, key1,
                )

    def test_dir_alg(self):
        key = OctKey.import_key("secret")
        self.assertRaises(
            InvalidKeyLengthError,
            encrypt_compact, {"alg": "dir", "enc": "A128GCM"}, b"j", key
        )
        for enc in JWE_ENC_MODELS:
            key = OctKey.generate_key(enc.cek_size)
            self.run_case('dir', enc.name, key, key)

    def test_AESGCM_alg(self):
        for size in [128, 192, 256]:
            key = OctKey.generate_key(size)
            self.run_cases([f"A{size}GCMKW"], key, key)

        key1 = OctKey.generate_key(128)
        key2 = OctKey.generate_key(128)
        protected = {"alg": "A128GCMKW", "enc": "A128CBC-HS256"}
        algorithms = ["A128GCMKW", "A128CBC-HS256"]
        value = encrypt_compact(protected, "i", key1, algorithms=algorithms)
        self.assertRaises(
            DecodeError,
            decrypt_compact,
            value, key2, algorithms=algorithms,
        )

    def test_PBES2HS_alg(self):
        algs = {
            "PBES2-HS256+A128KW": 128,
            "PBES2-HS384+A192KW": 192,
            "PBES2-HS512+A256KW": 256,
        }
        for alg in algs:
            key = OctKey.generate_key(algs[alg])
            self.run_cases([alg], key, key)

        key1 = OctKey.generate_key(128)
        key2 = OctKey.generate_key(128)
        protected = {"alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256"}
        algorithms = ["PBES2-HS256+A128KW", "A128CBC-HS256"]
        value = encrypt_compact(protected, "i", key1, algorithms=algorithms)
        self.assertRaises(
            DecodeError,
            decrypt_compact,
            value, key2, algorithms=algorithms,
        )

    def test_PBES2HS_with_header(self):
        key = OctKey.generate_key(128)
        protected = {
            "alg": "PBES2-HS256+A128KW",
            "enc": "A128CBC-HS256",
            "p2s": "QoGrcBpns_cLWCQPEVuA-g",
            "p2c": 1024,
        }
        registry = JWERegistry(algorithms=["PBES2-HS256+A128KW", "A128CBC-HS256"])
        value1 = encrypt_compact(protected, b"i", key, registry=registry)
        obj1 = decrypt_compact(value1, key, registry=registry)
        self.assertIn("p2c", obj1.headers())
        self.assertEqual(obj1.headers()["p2c"], 1024)

        # invalid type
        protected["p2c"] = "1024"
        self.assertRaises(
            ValueError,
            encrypt_compact,
            protected, b"i", key,
            registry=registry,
        )

    def test_with_zip_header(self):
        private_key: RSAKey = load_key('rsa-openssl-private.pem')
        public_key: RSAKey = load_key('rsa-openssl-public.pem')
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256", "zip": "DEF"}
        plaintext = b"hello"
        result = encrypt_compact(protected, plaintext, public_key)
        obj = decrypt_compact(result, private_key)
        self.assertEqual(obj.plaintext, plaintext)

    def test_invalid_compact_data(self):
        private_key: RSAKey = load_key('rsa-openssl-private.pem')
        value = b"a.b.c.d.e.f.g"
        self.assertRaises(ValueError, decrypt_compact, value, private_key)
        value = b"a.b.c.d.e"
        self.assertRaises(DecodeError, decrypt_compact, value, private_key)

        value = json_b64encode({"enc": "A128CBC-HS256"}) + b".b.c.d.e"
        self.assertRaises(MissingAlgorithmError, decrypt_compact, value, private_key)

        value = json_b64encode({"alg": "RSA-OAEP"}) + b".b.c.d.e"
        self.assertRaises(MissingEncryptionError, decrypt_compact, value, private_key)

    def test_with_key_set(self):
        keys = KeySet([
            OctKey.generate_key(),
            OctKey.generate_key(),
            RSAKey.generate_key(),
        ])
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        value = encrypt_compact(protected, b"foo", keys)
        obj = decrypt_compact(value, keys)
        self.assertEqual(obj.plaintext, b"foo")

    def test_compact_encryption(self):
        key: RSAKey = load_key('rsa-openssl-private.pem')
        protected = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256"}
        obj = CompactEncryption(protected, b"")
        self.assertEqual(obj.recipients, [])
        obj.attach_recipient(key, {"kid": "foo"})
        self.assertEqual(obj.protected["kid"], "foo")
