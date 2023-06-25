from unittest import TestCase
from joserfc import jws, jwt
from joserfc.errors import (
    InvalidPayloadError,
    InvalidTypeError,
    MissingClaimError,
)


class TestJWT(TestCase):
    def test_invalid_payboad(self):
        data = jws.serialize_compact({"alg": "HS256"}, b"hello", "secret")
        self.assertRaises(InvalidPayloadError, jwt.extract, data)
        self.assertRaises(InvalidPayloadError, jwt.decode, data, "secret")

    def test_invalid_type(self):
        data = jws.serialize_compact({"alg": "HS256", "typ": "JOSE"}, b'{"iss":"a"}', "secret")
        self.assertRaises(InvalidTypeError, jwt.decode, data, "secret")

    def test_extract_token(self):
        data = jws.serialize_compact({"alg": "HS256"}, b'{"iss":"a"}', "secret")
        token = jwt.extract(data)
        self.assertEqual(repr(token), "{'iss': 'a'}")

    def test_claims_registry(self):
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, "secret")
        token = jwt.decode(data, "secret")

        claims_registry = jwt.JWTClaimsRegistry(iss={"essential": True})
        self.assertRaises(MissingClaimError, claims_registry.validate, token.claims)

        data = jwt.encode({"alg": "HS256"}, {"iss": "a"}, "secret")
        obj = jwt.decode(data, "secret")
        self.assertEqual(obj.claims["iss"], "a")
