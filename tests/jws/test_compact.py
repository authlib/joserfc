from unittest import TestCase
from joserfc.jws import JWSRegistry, serialize_compact, deserialize_compact
from joserfc.jwk import OctKey, RSAKey, KeySet
from joserfc.errors import (
    BadSignatureError,
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
)


class TestCompact(TestCase):
    def test_registry_is_none(self):
        key = OctKey.import_key("secret")
        value = serialize_compact({"alg": "HS256"}, b"foo", key)
        expected = "eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0"
        self.assertEqual(value, expected)

        obj = deserialize_compact(value, key)
        self.assertEqual(obj.payload, b"foo")

    def test_bad_signature_error(self):
        key = OctKey.import_key("incorrect")
        value = b"eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0"
        self.assertRaises(BadSignatureError, deserialize_compact, value, key)

    def test_raise_unsupported_algorithm_error(self):
        key = OctKey.import_key("secret")
        self.assertRaises(UnsupportedAlgorithmError, serialize_compact, {"alg": "HS512"}, b"foo", key)
        self.assertRaises(UnsupportedAlgorithmError, serialize_compact, {"alg": "NOT"}, b"foo", key)

    def test_invalid_length(self):
        key = OctKey.import_key("secret")
        self.assertRaises(DecodeError, deserialize_compact, b"a.b.c.d", key)

    def test_no_invalid_header(self):
        # invalid base64
        value = b"abc.Zm9v.0pehoi"
        key = OctKey.import_key("secret")
        self.assertRaises(DecodeError, deserialize_compact, value, key)

        # no alg value
        value = b"eyJhIjoiYiJ9.Zm9v.0pehoi"
        self.assertRaises(MissingAlgorithmError, deserialize_compact, value, key)

    def test_invalid_payload(self):
        value = b"eyJhbGciOiJIUzI1NiJ9.a$b.0pehoi"
        key = OctKey.import_key("secret")
        self.assertRaises(DecodeError, deserialize_compact, value, key)

    def test_with_key_set(self):
        keys = KeySet(
            [
                OctKey.import_key("a"),
                OctKey.import_key("b"),
                OctKey.import_key("c"),
            ]
        )
        value = serialize_compact({"alg": "HS256"}, b"foo", keys)
        obj = deserialize_compact(value, keys)
        self.assertEqual(obj.payload, b"foo")

        keys.keys.append(RSAKey.generate_key(auto_kid=True))
        value = serialize_compact({"alg": "RS256"}, b"foo", keys)
        obj = deserialize_compact(value, keys)
        self.assertEqual(obj.payload, b"foo")

    def test_strict_check_header(self):
        header = {"alg": "HS256", "custom": "hi"}
        key = OctKey.import_key("secret")
        self.assertRaises(UnsupportedHeaderError, serialize_compact, header, b"hi", key)

        registry = JWSRegistry(strict_check_header=False)
        serialize_compact(header, b"hi", key, registry=registry)

    def test_non_canonical_signature_encoding(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.VI29GgHzuh2xfF0bkRYvZIsSuQnbTXSIvuRyt7RDrwo"[:-1] + "p"
        self.assertRaises(
            BadSignatureError,
            deserialize_compact,
            text,
            OctKey.import_key("secret")
        )
