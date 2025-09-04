from unittest import TestCase
from joserfc import jws
from joserfc.jwk import RSAKey, OctKey
from joserfc.registry import HeaderParameter
from joserfc.errors import (
    BadSignatureError,
    MissingKeyError,
    UnsupportedAlgorithmError,
    UnsupportedKeyUseError,
    UnsupportedKeyAlgorithmError,
    UnsupportedKeyOperationError,
    InvalidKeyTypeError,
    InvalidKeyCurveError,
    MissingHeaderError,
    MissingCritHeaderError,
    UnsupportedHeaderError,
    InvalidHeaderValueError,
)
from joserfc.util import urlsafe_b64encode
from tests.base import load_key


class TestJWSErrors(TestCase):
    key = OctKey.import_key("secret")

    def test_without_alg(self):
        self.assertRaises(MissingHeaderError, jws.serialize_compact, {"kid": "123"}, "i", self.key)

    def test_raise_unsupported_algorithm_error(self):
        registry = jws.JWSRegistry(algorithms=["HS256", "HS384", "HS512"])
        header = {"alg": "HS256"}
        jws.serialize_compact(header, "i", self.key, registry=registry)
        # raise error
        registry = jws.JWSRegistry(algorithms=["HS512"])
        self.assertRaises(UnsupportedAlgorithmError, jws.serialize_compact, header, "i", self.key, registry=registry)

    def test_without_key(self):
        self.assertRaises(MissingKeyError, jws.serialize_compact, {"alg": "HS256"}, "i", None)

        header = {"alg": "HS256"}
        text = jws.serialize_compact(header, "i", self.key)
        self.assertRaises(MissingKeyError, jws.deserialize_compact, text, None)

    def test_none_alg(self):
        header = {"alg": "none"}
        text = jws.serialize_compact(header, "i", None, algorithms=["none"])
        obj = jws.deserialize_compact(text, None, algorithms=["none"])
        self.assertEqual(obj.payload, b"i")
        # none alg has no signature
        text += "aQ"
        self.assertRaises(BadSignatureError, jws.deserialize_compact, text, None, algorithms=["none"])

    def test_header_invalid_type(self):
        # kid should be a string
        header = {"alg": "HS256", "kid": 123}
        self.assertRaises(
            InvalidHeaderValueError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

        # jwk should be a dict
        header = {"alg": "HS256", "jwk": "dict"}
        self.assertRaises(
            InvalidHeaderValueError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

        # jku should be a URL
        header = {"alg": "HS256", "jku": "url"}
        self.assertRaises(
            InvalidHeaderValueError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

        # x5c should be a chain of string
        header = {"alg": "HS256", "x5c": "url"}
        self.assertRaises(
            InvalidHeaderValueError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )
        header = {"alg": "HS256", "x5c": [1, 2]}
        self.assertRaises(
            InvalidHeaderValueError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

    def test_crit_header(self):
        header = {"alg": "HS256", "crit": ["kid"]}
        # missing kid header
        self.assertRaises(
            MissingCritHeaderError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

        header = {"alg": "HS256", "kid": "1", "crit": ["kid"]}
        jws.serialize_compact(header, "i", self.key)

    def test_unsupported_crit_header(self):
        header = {"alg": "HS256", "bob": "a", "crit": ["bob"]}
        self.assertRaises(
            UnsupportedHeaderError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )

        registry = jws.JWSRegistry(
            header_registry={
                "bob": HeaderParameter("Bob", "str"),
            }
        )
        # allow with custom header registry
        jws.serialize_compact(header, "i", self.key, registry=registry)

    def test_extra_header(self):
        header = {"alg": "HS256", "extra": "hi"}
        self.assertRaises(
            UnsupportedHeaderError,
            jws.serialize_compact,
            header,
            "i",
            self.key,
        )
        # bypass extra header
        registry = jws.JWSRegistry(strict_check_header=False)
        jws.serialize_compact(header, "i", self.key, registry=registry)

        # or use a header registry
        extra_header = {"extra": HeaderParameter("Extra header", "str", False)}
        registry = jws.JWSRegistry(header_registry=extra_header)
        jws.serialize_compact(header, "i", self.key, registry=registry)

    def test_rsa_invalid_signature(self):
        key1 = RSAKey.generate_key()
        key2 = RSAKey.generate_key()
        header = {"alg": "RS256"}
        text = jws.serialize_compact(header, "i", key1)
        self.assertRaises(BadSignatureError, jws.deserialize_compact, text, key2)

        header = {"alg": "PS256"}
        text = jws.serialize_compact(header, "i", key1, algorithms=["PS256"])
        self.assertRaises(BadSignatureError, jws.deserialize_compact, text, key2, algorithms=["PS256"])

    def test_ec_incorrect_curve(self):
        header = {"alg": "ES256"}
        key = load_key("ec-p512-private.pem")
        self.assertRaises(InvalidKeyCurveError, jws.serialize_compact, header, "i", key)

    def test_ec_invalid_signature(self):
        header = {"alg": "ES256"}
        key1 = load_key("ec-p256-alice.json")
        key2 = load_key("ec-p256-bob.json")
        text = jws.serialize_compact(header, "i", key1)
        self.assertRaises(BadSignatureError, jws.deserialize_compact, text, key2)

        parts = text.split(".")
        bad_text = ".".join(parts[:-1]) + "." + urlsafe_b64encode(b"abc").decode("utf-8")
        self.assertRaises(BadSignatureError, jws.deserialize_compact, bad_text, key1)

    def test_okp_bad_signature(self):
        header = {"alg": "EdDSA"}
        key1 = load_key("okp-ed448-private.pem")
        key2 = load_key("okp-ed25519-private.json")
        algorithms = ["EdDSA"]
        value = jws.serialize_json({"protected": header}, "i", key1, algorithms=algorithms)
        self.assertRaises(
            BadSignatureError,
            jws.deserialize_json,
            value,
            key2,
            algorithms=algorithms,
        )


class TestJWSWithKeyErrors(TestCase):
    def test_invalid_key_use(self):
        key = OctKey.generate_key(parameters={"use": "enc"})
        header = {"alg": "HS256"}
        self.assertRaises(UnsupportedKeyUseError, jws.serialize_compact, header, "i", key)

    def test_invalid_key_alg(self):
        key = OctKey.generate_key(parameters={"alg": "HS512"})
        header = {"alg": "HS256"}
        self.assertRaises(UnsupportedKeyAlgorithmError, jws.serialize_compact, header, "i", key)

    def test_invalid_key_ops(self):
        key = OctKey.generate_key(parameters={"key_ops": ["verify"]})
        header = {"alg": "HS256"}
        self.assertRaises(UnsupportedKeyOperationError, jws.serialize_compact, header, "i", key)

    def test_invalid_key_type(self):
        key = OctKey.generate_key()
        header = {"alg": "RS256"}
        self.assertRaises(InvalidKeyTypeError, jws.serialize_compact, header, "i", key)
