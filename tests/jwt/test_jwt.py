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

    def test_registry(self):
        claims_requests = jwt.JWTClaimsRequests(iss={"essential": True})
        registry = jwt.JWTRegistry(claims_requests=claims_requests)
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, "secret")
        self.assertRaises(MissingClaimError, jwt.decode, data, "secret", registry)

        data = jwt.encode({"alg": "HS256"}, {"iss": "a"}, "secret")
        obj = jwt.decode(data, "secret", registry)
        self.assertEqual(obj.claims["iss"], "a")
