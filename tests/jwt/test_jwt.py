from unittest import TestCase
from joserfc import jws, jwe, jwt
from joserfc.jwk import OctKey
from joserfc.errors import (
    InvalidPayloadError,
    MissingClaimError,
    UnsupportedHeaderError,
    DecodeError,
)


class TestJWT(TestCase):
    def test_invalid_payload(self):
        key = OctKey.import_key("secret")
        data = jws.serialize_compact({"alg": "HS256"}, b"hello", key)
        self.assertRaises(InvalidPayloadError, jwt.decode, data, key)

    def test_claims_registry(self):
        key = OctKey.import_key("secret")
        data = jwt.encode({"alg": "HS256"}, {"sub": "a"}, key)
        token = jwt.decode(data, key)

        claims_registry = jwt.JWTClaimsRegistry(iss={"essential": True})
        self.assertRaises(MissingClaimError, claims_registry.validate, token.claims)

        data = jwt.encode({"alg": "HS256"}, {"iss": "a"}, key)
        obj = jwt.decode(data, key)
        self.assertEqual(obj.claims["iss"], "a")

    def test_jwe_format(self):
        header = {"alg": "A128KW", "enc": "A128GCM"}
        claims = {"iss": "https://authlib.org"}
        key = OctKey.generate_key(128)
        registry = jwe.JWERegistry()
        result = jwt.encode(header, claims, key, registry=registry)
        self.assertEqual(result.count("."), 4)

        token = jwt.decode(result, key, registry=registry)
        self.assertEqual(token.claims, claims)

    def test_using_registry(self):
        key = OctKey.generate_key(128)
        value1 = jwt.encode({"alg": "HS256"}, {"sub": "a"}, key, registry=jws.JWSRegistry())
        jwt.decode(value1, key, registry=jws.JWSRegistry())
        value2 = jwt.encode({"alg": "A128KW", "enc": "A128GCM"}, {"sub": "a"}, key, registry=jwe.JWERegistry())
        jwt.decode(value2, key, registry=jwe.JWERegistry())

        self.assertRaises(
            KeyError,
            jwt.encode,
            {"alg": "HS256"},
            {"sub": "a"},
            key,
            registry=jwe.JWERegistry(),
        )
        self.assertRaises(
            UnsupportedHeaderError,
            jwt.encode,
            {"alg": "A128KW", "enc": "A128GCM"},
            {"sub": "a"},
            key,
            registry=jws.JWSRegistry(),
        )
        self.assertRaises(
            ValueError,
            jwt.decode,
            value1,
            key,
            registry=jwe.JWERegistry(),
        )
        self.assertRaises(
            DecodeError,
            jwt.decode,
            value2,
            key,
            registry=jws.JWSRegistry(),
        )
