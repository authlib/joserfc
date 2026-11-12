import unittest

from joserfc import jws
from joserfc.errors import (
    DecodeError,
    InvalidHeaderValueError,
    JoseError,
)
from joserfc.jwk import OctKey


class TestDeserializeJSONMalformed(unittest.TestCase):
    """Malformed JWS JSON serialization objects must raise JoseError
    subclasses instead of raw TypeError / AttributeError / KeyError."""

    def setUp(self) -> None:
        self.key = OctKey.import_key("secret")

    def _deserialize(self, data):
        return jws.deserialize_json(data, self.key)

    def test_signature_member_is_not_an_object(self):
        data = {"payload": "eyJhIjoxfQ", "signatures": [123]}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

        data = {"payload": "eyJhIjoxfQ", "signatures": [None]}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

        data = {"payload": "eyJhIjoxfQ", "signatures": ["signature"]}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

    def test_signatures_is_not_a_list(self):
        data = {"payload": "eyJhIjoxfQ", "signatures": 123}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

        data = {"payload": "eyJhIjoxfQ", "signatures": "invalid"}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

    def test_invalid_header_value(self):
        data = {"payload": "eyJhIjoxfQ", "signatures": [{"header": 123}]}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

        data = {"payload": "eyJhIjoxfQ", "protected": "eyJhbGciOiJIUzI1NiJ9", "signature": "AA", "header": 123}
        with self.assertRaises(InvalidHeaderValueError):
            self._deserialize(data)

    def test_invalid_payload_member(self):
        for payload in (123, None, ["a"]):
            data = {"payload": payload, "signatures": [{"protected": "eyJhbGciOiJIUzI1NiJ9"}]}
            with self.assertRaises(DecodeError):
                self._deserialize(data)

            data = {"payload": payload, "protected": "eyJhbGciOiJIUzI1NiJ9", "signature": "AA"}
            with self.assertRaises(DecodeError):
                self._deserialize(data)

    def test_missing_payload_member(self):
        data = {"signatures": [{"protected": "eyJhbGciOiJIUzI1NiJ9"}]}
        with self.assertRaises(DecodeError):
            self._deserialize(data)

        data = {"protected": "eyJhbGciOiJIUzI1NiJ9", "signature": "AA"}
        with self.assertRaises(DecodeError):
            self._deserialize(data)

    def test_missing_signature_member(self):
        data = {"payload": "eyJhIjoxfQ", "protected": "eyJhbGciOiJIUzI1NiJ9"}
        with self.assertRaises(DecodeError):
            self._deserialize(data)

    def test_no_raw_exceptions_on_valid_shape(self):
        # a structurally valid (even if unverifiable) token must still
        # surface the library's own error classes
        data = {"payload": "eyJhIjoxfQ", "protected": "eyJhbGciOiJIUzI1NiJ9", "signature": "AA"}
        with self.assertRaises(JoseError):
            self._deserialize(data)
