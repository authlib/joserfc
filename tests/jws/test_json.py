from unittest import TestCase
from joserfc.jws import serialize_json, deserialize_json, detach_content
from joserfc.jwk import RSAKey, KeySet
from joserfc.errors import DecodeError, BadSignatureError
from tests.base import load_key


class TestJSON(TestCase):
    def test_serialize_json(self):
        key: RSAKey = load_key("rsa-openssl-private.pem")
        member = {"protected": {"alg": "RS256"}}

        # flattened
        value = serialize_json(member, b"hello", key)
        self.assertIn("signature", value)
        self.assertNotIn("signatures", value)

        obj = deserialize_json(value, key)
        self.assertEqual(obj.payload, b"hello")
        self.assertEqual(obj.headers(), {"alg": "RS256"})

        # general
        value = serialize_json([member], b"hello", key)
        self.assertNotIn("signature", value)
        self.assertIn("signatures", value)

        obj = deserialize_json(value, key)
        self.assertEqual(obj.payload, b"hello")

    def test_serialize_with_unprotected_header(self):
        key: RSAKey = load_key("rsa-openssl-private.pem")
        member = {"protected": {"alg": "RS256"}, "header": {"kid": "alice"}}
        value = serialize_json(member, b"hello", key)
        self.assertIn("header", value)
        self.assertEqual(value["header"], member["header"])

        value = serialize_json([member], b"hello", key)
        self.assertIn("signatures", value)

        value = value["signatures"][0]
        self.assertIn("header", value)
        self.assertEqual(value["header"], member["header"])

    def test_use_key_set(self):
        key1 = load_key("ec-p256-alice.json", {"kid": "alice"})
        key2 = load_key("ec-p256-bob.json", {"kid": "bob"})
        keys = KeySet([key1, key2])
        member = {"protected": {"alg": "ES256"}}
        value = serialize_json(member, b"hello", keys)
        self.assertIn("header", value)
        self.assertIn("kid", value["header"])

        # this will always pick alice key
        member = {"protected": {"alg": "ES256"}, "header": {"kid": "alice"}}
        value = serialize_json(member, b"hello", keys)
        self.assertEqual(value["header"], {"kid": "alice"})

        # header can also be an empty value
        member = {"protected": {"alg": "ES256"}, "header": {}}
        value = serialize_json(member, b"hello", keys)
        self.assertIn("kid", value["header"])

    def test_detach_content(self):
        member = {"protected": {"alg": "ES256"}}
        key = load_key("ec-p256-alice.json")
        value = serialize_json(member, b"hello", key)
        self.assertIn("payload", value)
        new_value = detach_content(value)
        self.assertNotIn("payload", new_value)
        # detach again will not raise error
        detach_content(new_value)

    def test_invalid_payload(self):
        member = {"protected": {"alg": "ES256"}}
        key = load_key("ec-p256-alice.json")
        value = serialize_json(member, b"hello", key)
        value["payload"] = "a"
        self.assertRaises(DecodeError, deserialize_json, value, key)
        value = serialize_json([member], b"hello", key)
        value["payload"] = "a"
        self.assertRaises(DecodeError, deserialize_json, value, key)

    def test_bad_signature(self):
        member = {"protected": {"alg": "ES256"}}
        key1 = load_key("ec-p256-alice.json")
        key2 = load_key("ec-p256-bob.json")
        value = serialize_json(member, b"hello", key1)
        self.assertRaises(BadSignatureError, deserialize_json, value, key2)
        value = serialize_json([member], b"hello", key1)
        self.assertRaises(BadSignatureError, deserialize_json, value, key2)

    def test_with_public_header(self):
        key: RSAKey = load_key("rsa-openssl-private.pem")
        member = {"header": {"alg": "RS256", "kid": "abc"}}
        value = serialize_json(member, b"hello", key)
        self.assertIn("header", value)
        obj = deserialize_json(value, key)
        self.assertEqual(obj.payload, b"hello")
        self.assertEqual(obj.headers(), {"alg": "RS256", "kid": "abc"})
