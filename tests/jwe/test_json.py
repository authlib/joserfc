from unittest import TestCase
from joserfc import jwe
from joserfc.jwe import GeneralJSONEncryption, FlattenedJSONEncryption
from joserfc.jwa import JWEKeyEncryption
from joserfc.jwk import KeySet, RSAKey, ECKey, OctKey
from joserfc.errors import (
    DecodeError,
    ConflictAlgorithmError,
    InvalidKeyTypeError,
    ExceededSizeError,
)


class CountingKeyEncryption(JWEKeyEncryption):
    name = "TEST-COUNT"
    description = "Counting test key encryption"
    key_types = ["oct"]

    def __init__(self):
        self.decrypt_count = 0

    def encrypt_cek(self, cek, recipient):
        return cek

    def decrypt_cek(self, recipient):
        self.decrypt_count += 1
        assert recipient.encrypted_key is not None
        return recipient.encrypted_key


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

    def test_general_json_without_recipients(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        value = jwe.encrypt_json(obj, None)
        value["recipients"] = []
        self.assertRaises(DecodeError, jwe.decrypt_json, value, self.rsa_key)

    def test_general_json_without_encrypted_key(self):
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        obj.add_recipient({"alg": "RSA-OAEP"}, self.rsa_key)
        value = jwe.encrypt_json(obj, None)
        del value["recipients"][0]["encrypted_key"]
        self.assertRaises(DecodeError, jwe.decrypt_json, value, self.rsa_key)

    def test_general_json_recipients_exceeded_size_error(self):
        key = OctKey.generate_key(128)
        limit = jwe.JWERegistry.max_recipients
        obj = GeneralJSONEncryption({"enc": "A128CBC-HS256"}, b"i")
        for _ in range(limit + 1):
            obj.add_recipient({"alg": "A128KW"}, key)

        value = jwe.encrypt_json(obj, None)
        self.assertRaises(ExceededSizeError, jwe.decrypt_json, value, key)

        registry = jwe.JWERegistry(max_recipients=limit + 1)
        obj1 = jwe.decrypt_json(value, key, registry=registry)
        self.assertEqual(obj1.plaintext, b"i")

    def test_verify_one_recipient_stops_after_success(self):
        key = OctKey.generate_key(128)
        alg = CountingKeyEncryption()
        jwe.JWERegistry.register(alg)
        try:
            registry = jwe.JWERegistry(
                algorithms=[alg.name, "A128GCM"],
                verify_all_recipients=False,
            )
            obj = GeneralJSONEncryption({"enc": "A128GCM"}, b"i")
            obj.add_recipient({"alg": alg.name}, key)
            obj.add_recipient({"alg": alg.name}, key)
            value = jwe.encrypt_json(obj, None, registry=registry)
            alg.decrypt_count = 0
            obj1 = jwe.decrypt_json(value, key, registry=registry)
        finally:
            del jwe.JWERegistry.algorithms["alg"][alg.name]

        self.assertEqual(obj1.plaintext, b"i")
        self.assertEqual(alg.decrypt_count, 1)

    def test_flattened_encryption(self):
        key = OctKey.generate_key(128)
        protected = {"enc": "A128CBC-HS256"}
        plaintext = b"hello world"
        obj0 = FlattenedJSONEncryption(protected, plaintext)
        obj0.add_recipient({"alg": "A128KW"})
        value = jwe.encrypt_json(obj0, key)
        obj1 = jwe.decrypt_json(value, key)
        self.assertEqual(obj1.plaintext, plaintext)

        obj2 = FlattenedJSONEncryption(protected, plaintext)
        obj2.add_recipient({"alg": "A128KW"}, key)
        value = jwe.encrypt_json(obj0, None)
        obj3 = jwe.decrypt_json(value, key)
        self.assertEqual(obj3.plaintext, plaintext)

    def test_flattened_json_without_encrypted_key(self):
        key = OctKey.generate_key(128)
        obj = FlattenedJSONEncryption({"enc": "A128CBC-HS256"}, b"hello world")
        obj.add_recipient({"alg": "A128KW"}, key)
        value = jwe.encrypt_json(obj, None)
        del value["encrypted_key"]
        self.assertRaises(DecodeError, jwe.decrypt_json, value, key)
