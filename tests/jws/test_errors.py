from unittest import TestCase
from joserfc import jws
from joserfc.jwk import RSAKey
from joserfc.errors import BadSignatureError
from tests.keys import load_key


class TestJWSErrors(TestCase):
    def test_none_alg(self):
        header = {"alg": "none"}
        text = jws.serialize_compact(
            header, "i", "secret",
            algorithms=["none"]
        )
        self.assertRaises(
            BadSignatureError,
            jws.deserialize_compact,
            text, "secret",
            algorithms=["none"]
        )

    def test_rsa_invalid_signature(self):
        key1 = RSAKey.generate_key()
        key2 = RSAKey.generate_key()
        header = {"alg": "RS256"}
        text = jws.serialize_compact(header, "i", key1)
        self.assertRaises(
            BadSignatureError,
            jws.deserialize_compact,
            text, key2
        )

        header = {"alg": "PS256"}
        text = jws.serialize_compact(
            header, "i", key1,
            algorithms=["PS256"]
        )
        self.assertRaises(
            BadSignatureError,
            jws.deserialize_compact,
            text, key2,
            algorithms=["PS256"]
        )

    def test_ec_incorrect_curve(self):
        header = {"alg": "ES256"}
        key = load_key("ec-p512-private.pem")
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", key
        )

    def test_ec_invalid_signature(self):
        header = {"alg": "ES256"}
        key1 = load_key("ec-p256-alice.json")
        key2 = load_key("ec-p256-bob.json")
        text = jws.serialize_compact(header, "i", key1)
        self.assertRaises(
            BadSignatureError,
            jws.deserialize_compact,
            text, key2
        )
