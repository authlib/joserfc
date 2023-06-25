import time
import datetime
from unittest import TestCase
from joserfc import jwt
from joserfc.errors import (
    InvalidClaimError,
    MissingClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


class TestJWTClaims(TestCase):
    def test_convert_time(self):
        now = datetime.datetime.now()
        encoded_text = jwt.encode({"alg": "HS256"}, {"iat": now}, "secret")
        decoded_data = jwt.decode(encoded_text, "secret")
        self.assertIsInstance(decoded_data.claims["iat"], int)

    def test_essential_claims(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"iss": "a"})

        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True}, iss={"essential": True})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"sub": "a"})

        claims_requests.validate({"sub": "a", "iss": "a", "name": "joserfc"})

    def test_option_value(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "value": "123"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": "a"})
        claims_requests.validate({"sub": "123"})

    def test_option_values(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "values": ["1", "2"]})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": "a"})
        claims_requests.validate({"sub": "1"})
        claims_requests.validate({"sub": "2"})

    def test_int_claims(self):
        now = int(time.time())
        claims_requests = jwt.JWTClaimsRegistry(now=now)
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"exp": "s"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"nbf": "s"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"iat": "s"})

        self.assertRaises(ExpiredTokenError, claims_requests.validate, {"exp": now - 100})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"nbf": now + 100})

        claims_requests.validate({"exp": now + 100, "nbf": now - 100, "iat": now})

    def test_validate_aud(self):
        claims_requests = jwt.JWTClaimsRegistry(aud={"essential": True, "value": "a"})

        # missing aud
        self.assertRaises(MissingClaimError, claims_requests.validate, {"iss": "a"})

        # invalid value
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"aud": "b"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"aud": ["b"]})

        # valid value
        claims_requests.validate({"aud": "a"})
        claims_requests.validate({"aud": ["a"]})

        # use option values
        claims_requests = jwt.JWTClaimsRegistry(aud={"essential": True, "values": ["a", "b"]})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"aud": "c"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"aud": ["c"]})

        claims_requests.validate({"aud": "a"})
        claims_requests.validate({"aud": "b"})
        claims_requests.validate({"aud": ["a"]})
        claims_requests.validate({"aud": ["b"]})
        claims_requests.validate({"aud": ["a", "b"]})
        claims_requests.validate({"aud": ["a", "c"]})

        # do not validate
        claims_requests = jwt.JWTClaimsRegistry()
        claims_requests.validate({"aud": "a"})

        claims_requests = jwt.JWTClaimsRegistry(aud={"essential": True})
        claims_requests.validate({"aud": "a"})
