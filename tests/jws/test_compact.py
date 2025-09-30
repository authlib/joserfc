from unittest import TestCase
from joserfc.jws import (
    JWSRegistry,
    serialize_compact,
    deserialize_compact,
    detach_content,
)
from joserfc.jwk import OctKey, RSAKey, KeySet
from joserfc.errors import (
    BadSignatureError,
    DecodeError,
    MissingAlgorithmError,
    UnsupportedAlgorithmError,
    UnsupportedHeaderError,
    ExceededSizeError,
)
from joserfc.util import urlsafe_b64encode, json_b64encode


class TestCompact(TestCase):
    key = OctKey.import_key("secret")

    def test_registry_is_none(self):
        value = serialize_compact({"alg": "HS256"}, b"foo", self.key)
        expected = "eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0"
        self.assertEqual(value, expected)

        obj = deserialize_compact(value, self.key)
        self.assertEqual(obj.payload, b"foo")

    def test_bad_signature_error(self):
        key = OctKey.import_key("incorrect")
        value = b"eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0"
        self.assertRaises(BadSignatureError, deserialize_compact, value, key)

    def test_raise_unsupported_algorithm_error(self):
        self.assertRaises(UnsupportedAlgorithmError, serialize_compact, {"alg": "HS512"}, b"foo", self.key)
        self.assertRaises(UnsupportedAlgorithmError, serialize_compact, {"alg": "NOT"}, b"foo", self.key)

    def test_invalid_length(self):
        self.assertRaises(DecodeError, deserialize_compact, b"a.b.c.d", self.key)

    def test_no_invalid_header(self):
        # invalid base64
        value = b"abc.Zm9v.0pehoi"
        self.assertRaises(DecodeError, deserialize_compact, value, self.key)

        # no alg value
        value = b"eyJhIjoiYiJ9.Zm9v.0pehoi"
        self.assertRaises(MissingAlgorithmError, deserialize_compact, value, self.key)

    def test_invalid_payload(self):
        value = b"eyJhbGciOiJIUzI1NiJ9.a$b.0pehoi"
        self.assertRaises(DecodeError, deserialize_compact, value, self.key)

    def test_header_exceeded_size_error(self):
        exceeded_header = json_b64encode({f"a{i}": f"a{i}" for i in range(1000)})
        other = urlsafe_b64encode(b"o")
        fake_jws = exceeded_header + b"." + other + b"." + other
        self.assertRaises(ExceededSizeError, deserialize_compact, fake_jws, self.key)

    def test_payload_exceeded_size_error(self):
        header = json_b64encode({"alg": "HS256"})
        exceeded_payload = urlsafe_b64encode(("o" * 10000).encode("utf8"))
        fake_jws = header + b"." + exceeded_payload + b"." + urlsafe_b64encode(b"o")
        self.assertRaises(ExceededSizeError, deserialize_compact, fake_jws, self.key)

    def test_signature_exceeded_size_error(self):
        header = json_b64encode({"alg": "HS256"})
        exceeded_signature = urlsafe_b64encode(("o" * 1000).encode("utf8"))
        fake_jws = header + b"." + urlsafe_b64encode(b"o") + b"." + exceeded_signature
        self.assertRaises(ExceededSizeError, deserialize_compact, fake_jws, self.key)

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
        self.assertRaises(UnsupportedHeaderError, serialize_compact, header, b"hi", self.key)

        registry = JWSRegistry(strict_check_header=False)
        serialize_compact(header, b"hi", self.key, registry=registry)

    def test_non_canonical_signature_encoding(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.VI29GgHzuh2xfF0bkRYvZIsSuQnbTXSIvuRyt7RDrwo"[:-1] + "p"
        self.assertRaises(BadSignatureError, deserialize_compact, text, OctKey.import_key("secret"))

    def test_detached_content(self):
        value = detach_content(serialize_compact({"alg": "HS256"}, b"foo", self.key))
        expected = "eyJhbGciOiJIUzI1NiJ9..0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0"
        self.assertEqual(value, expected)
        obj = deserialize_compact(value, self.key, payload=b"foo")
        self.assertEqual(obj.payload, b"foo")
