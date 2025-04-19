from unittest import TestCase
from joserfc import jwe
from joserfc.jwe import GeneralJSONEncryption
from joserfc.jwk import KeySet, RSAKey, ECKey, OctKey
from joserfc.errors import (
    DecodeError,
    ConflictAlgorithmError,
    InvalidKeyTypeError,
)


class TestJWEJSON(TestCase):
    rsa_key = RSAKey.generate_key()
    ec_key = ECKey.generate_key()

    def test_multiple_recipients_with_key(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        obj.add_recipient({"alg": "ECDH-ES+A128KW"}, self.ec_key)
        value = jwe.encrypt_json(obj, None)
        self.assertIn("recipients", value)
        self.assertEqual(len(value["recipients"]), 2)

    def test_multiple_recipients_without_key(self):
        key1 = RSAKey.generate_key(parameters={"kid": "rsa"})
        key2 = ECKey.generate_key(parameters={"kid": "ec"})
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "RSA-OAEP", "kid": "rsa"})
        obj.add_recipient({"alg": "ECDH-ES+A128KW", "kid": "ec"})
        value = jwe.encrypt_json(obj, KeySet([key1, key2]))
        self.assertIn("recipients", value)
        self.assertEqual(len(value["recipients"]), 2)

    def test_multiple_recipients_with_direct_mode(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "dir"}, OctKey.generate_key())
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        self.assertRaises(
            ConflictAlgorithmError,
            jwe.encrypt_json,
            obj,
            None,
        )

    def test_with_aad(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i", aad=b"foo")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        value = jwe.encrypt_json(obj, None)
        obj1 = jwe.decrypt_json(value, self.rsa_key)
        self.assertEqual(obj1.aad, b"foo")

    def test_decode_multiple_recipients(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        obj.add_recipient({"alg": "ECDH-ES+A128KW"}, self.ec_key)
        value = jwe.encrypt_json(obj, None)
        self.assertRaises(
            InvalidKeyTypeError,
            jwe.decrypt_json,
            value,
            self.rsa_key,
        )
        registry = jwe.JWERegistry(verify_all_recipients=False)
        obj1 = jwe.decrypt_json(value, self.rsa_key, registry=registry)
        self.assertEqual(obj1.plaintext, b"i")

        key3 = OctKey.generate_key()
        self.assertRaises(
            DecodeError,
            jwe.decrypt_json,
            value,
            key3,
            registry=registry,
        )
