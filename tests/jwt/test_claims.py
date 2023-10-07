import time
import datetime
from unittest import TestCase
from joserfc import jwt
from joserfc.errors import (
    InsecureClaimError,
    InvalidClaimError,
    MissingClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


class TestJWTClaims(TestCase):
    def test_check_sensitive_data(self):
        jwt.check_sensitive_data({})
        jwt.check_sensitive_data({"card": 123})

        for key in ("password", "token", "secret", "secret_key", "api_key"):
            claims = {key: "123"}
            self.assertRaises(
                InsecureClaimError,
                jwt.check_sensitive_data,
                claims
            )

        claims = {"card": "6011000000000000"}
        self.assertRaises(
            InsecureClaimError,
            jwt.check_sensitive_data,
            claims
        )

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

    def test_essential_empty_value(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"sub": None})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": ""})
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "allow_blank": True})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"sub": None})
        claims_requests.validate({"sub": ""})

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

        claims_requests.validate({"exp": now + 100, "nbf": now - 100, "iat": now})
        self.assertRaises(ExpiredTokenError, claims_requests.validate, {"exp": now - 100})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"nbf": now + 100})

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

    def test_validate_iat(self):
        now = int(time.time())
        claims_requests = jwt.JWTClaimsRegistry(now=now, leeway=500)
        claims_requests.validate({"iat": now})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"iat": now + 1000})

    def test_validate_nbf(self):
        now = int(time.time())
        claims_requests = jwt.JWTClaimsRegistry(now=now, leeway=500)
        claims_requests.validate({"nbf": now})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"nbf": now + 1000})
