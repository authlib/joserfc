from unittest import TestCase
from joserfc import jws, jwe, jwt
from joserfc.jwk import OctKey, GuestProtocol, Key, import_key
from joserfc.errors import (
    InvalidPayloadError,
    MissingClaimError,
    UnsupportedHeaderError,
    DecodeError,
)


def use_embedded_jwk(obj: GuestProtocol) -> Key:
    headers = obj.headers()
    return import_key(headers["jwk"])


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

    def test_with_embedded_jwk(self):
        value = (
            "eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJ4IjoiVU05ZzVuS25aWFlvdldBbE"
            "03NmNMejl2VG96UmpfX0NIVV9kT2wtZ09vRSIsInkiOiJkczhhZVF3MWwy"
            "Y0RDQTdiQ2tPTnZ3REtwWEFidFhqdnFDbGVZSDhXc19VIiwia3R5IjoiRU"
            "MifSwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJ1cm46ZXhhbXBsZTppc3N1Z"
            "XIiLCJhdWQiOiJ1cm46ZXhhbXBsZTphdWRpZW5jZSIsImlhdCI6MTYwNDU"
            "4MDc5NH0.60boak3_dErnW47ZPty1C0nrjeVq86EN_eK0GOq6K8w2OA0th"
            "KoBxFK4j-NuU9yZ_A9UKGxPT_G87DladBaV9g"
        )
        token = jwt.decode(value, use_embedded_jwk)
        self.assertEqual(token.claims["iss"], "urn:example:issuer")
