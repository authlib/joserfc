from unittest import TestCase
from joserfc import jws, jwt
from joserfc.jwk import OctKey
from joserfc.errors import (
    InvalidPayloadError,
    InvalidTypeError,
    MissingClaimError,
)


class TestJWT(TestCase):
    def test_invalid_payload(self):
        data = jws.serialize_compact({"alg": "HS256"}, b"hello", "secret")
        self.assertRaises(InvalidPayloadError, jwt.decode, data, "secret")

    def test_invalid_type(self):
        data = jws.serialize_compact({"alg": "HS256", "typ": "JOSE"}, b'{"iss":"a"}', "secret")
        self.assertRaises(InvalidTypeError, jwt.decode, data, "secret")

    def test_claims_registry(self):
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, "secret")
        token = jwt.decode(data, "secret")

        claims_registry = jwt.JWTClaimsRegistry(iss={"essential": True})
        self.assertRaises(MissingClaimError, claims_registry.validate, token.claims)

        data = jwt.encode({"alg": "HS256"}, {"iss": "a"}, "secret")
        obj = jwt.decode(data, "secret")
        self.assertEqual(obj.claims["iss"], "a")

    def test_jwe_format(self):
        header = {"alg": "A128KW", "enc": "A128GCM"}
        claims = {"iss": "https://authlib.org"}
        key = OctKey.generate_key(128)
        result = jwt.encode(header, claims, key)
        self.assertEqual(result.count('.'), 4)

        token = jwt.decode(result, key)
        self.assertEqual(token.claims, claims)
