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

    def test_header_invalid_type(self):
        # kid should be a string
        header = {"alg": "HS256", "kid": 123}
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )

        # jwk should be a dict
        header = {"alg": "HS256", "jwk": "dict"}
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )

        # jku should be a URL
        header = {"alg": "HS256", "jku": "url"}
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )

        # x5c should be a chain of string
        header = {"alg": "HS256", "x5c": "url"}
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )

    def test_crit_header(self):
        header = {"alg": "HS256", "crit": ["kid"]}
        # missing kid header
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )

        header = {"alg": "HS256", "kid": "1", "crit": ["kid"]}
        jws.serialize_compact(header, "i", "secret")

    def test_extra_header(self):
        header = {"alg": "HS256", "extra": "hi"}
        self.assertRaises(
            ValueError,
            jws.serialize_compact,
            header, "i", "secret",
        )
        # bypass extra header
        registry = jws.JWSRegistry(strict_check_header=False)
        jws.serialize_compact(header, "i", "secret", registry=registry)

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
