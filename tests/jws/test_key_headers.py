import base64
import json
from unittest import TestCase

from joserfc import jws, jwt
from joserfc.errors import (
    MissingHeaderError,
    UnsupportedAlgorithmError,
    UnsupportedKeyAlgorithmError,
)
from joserfc.jwk import ECKey, KeySet, OctKey, RSAKey


def _decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


class TestKeyHeaders(TestCase):
    def test_alg_and_kid_filled_from_key(self):
        key = ECKey.generate_key("P-256", parameters={"alg": "ES256", "kid": "k1"}, private=True)

        token = jwt.encode({}, {"sub": "a"}, key)

        header = jwt.decode(token, key).header
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["kid"], "k1")

    def test_explicit_header_values_win(self):
        key = ECKey.generate_key("P-256", parameters={"alg": "ES256", "kid": "k1"}, private=True)

        token = jwt.encode({"kid": "explicit"}, {"sub": "a"}, key)

        header = jwt.decode(token, key).header
        self.assertEqual(header["kid"], "explicit")
        self.assertEqual(header["alg"], "ES256")

    def test_explicit_mismatched_alg_still_fails(self):
        key = ECKey.generate_key("P-256", parameters={"alg": "ES256"}, private=True)

        self.assertRaises(
            UnsupportedKeyAlgorithmError,
            jwt.encode,
            {"alg": "ES384"},
            {"sub": "a"},
            key,
            ["ES384"],
        )

    def test_alg_from_key_must_be_allowed(self):
        key = OctKey.import_key("a-valid-secret", parameters={"alg": "HS512"})

        self.assertRaises(
            UnsupportedAlgorithmError,
            jwt.encode,
            {},
            {"sub": "a"},
            key,
            ["HS256"],
        )

    def test_no_alg_on_key_or_header_still_fails(self):
        key = RSAKey.generate_key(2048, private=True)

        self.assertRaises(MissingHeaderError, jwt.encode, {}, {"sub": "a"}, key)

    def test_keyset_without_header_alg_still_fails(self):
        key = ECKey.generate_key("P-256", parameters={"alg": "ES256", "kid": "k1"}, private=True)

        self.assertRaises(MissingHeaderError, jwt.encode, {}, {"sub": "a"}, KeySet([key]))

    def test_json_serialization_fills_from_key(self):
        key = ECKey.generate_key("P-256", parameters={"alg": "ES256", "kid": "k1"}, private=True)

        obj = jws.serialize_json({"protected": {}}, b"payload", key)

        self.assertEqual(_decode_segment(obj["protected"]), {"alg": "ES256"})
        self.assertEqual(obj["header"]["kid"], "k1")
        jws.deserialize_json(obj, key)

    def test_general_json_serialization_fills_from_key(self):
        key = OctKey.import_key("a-valid-secret", parameters={"alg": "HS256", "kid": "k1"})

        obj = jws.serialize_json([{"protected": {}}, {"protected": {}}], b"payload", key)

        for signature in obj["signatures"]:
            self.assertEqual(_decode_segment(signature["protected"]), {"alg": "HS256"})
            self.assertEqual(signature["header"]["kid"], "k1")
        jws.deserialize_json(obj, key)
