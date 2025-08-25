import time
import datetime
import json
import uuid
from unittest import TestCase
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import (
    InsecureClaimError,
    InvalidClaimError,
    MissingClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


class UUIDEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, uuid.UUID):
            return str(o)
        return super().default(o)


class TestJWTClaims(TestCase):
    def test_check_sensitive_data(self):
        jwt.check_sensitive_data({})
        jwt.check_sensitive_data({"card": 123})

        for key in ("password", "token", "secret", "secret_key", "api_key"):
            claims = {key: "123"}
            self.assertRaises(InsecureClaimError, jwt.check_sensitive_data, claims)

        claims = {"card": "6011000000000000"}
        self.assertRaises(InsecureClaimError, jwt.check_sensitive_data, claims)

    def test_convert_time(self):
        key = OctKey.import_key("secret")
        now = datetime.datetime.now()
        encoded_text = jwt.encode({"alg": "HS256"}, {"iat": now}, key)
        decoded_data = jwt.decode(encoded_text, key)
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

    def test_essential_false_value(self):
        claims_requests = jwt.JWTClaimsRegistry(foo={"essential": True})
        claims_requests.validate({"foo": False})
        claims_requests.validate({"foo": 0})

    def test_option_value(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "value": "123"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": "a"})
        claims_requests.validate({"sub": "123"})
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "value": True})
        claims_requests.validate({"sub": True})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": False})
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "value": False})
        claims_requests.validate({"sub": False})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": True})

    def test_option_values(self):
        claims_requests = jwt.JWTClaimsRegistry(sub={"essential": True, "values": ["1", "2", True, False]})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"sub": "a"})
        claims_requests.validate({"sub": "1"})
        claims_requests.validate({"sub": "2"})
        claims_requests.validate({"sub": True})
        claims_requests.validate({"sub": False})

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
        claims_requests = jwt.JWTClaimsRegistry(leeway=500)
        now = int(time.time())
        claims_requests.validate({"iat": now})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"iat": now + 1000})

    def test_validate_nbf(self):
        claims_requests = jwt.JWTClaimsRegistry(leeway=500)
        now = int(time.time())
        claims_requests.validate({"nbf": now})
        self.assertRaises(InvalidTokenError, claims_requests.validate, {"nbf": now + 1000})

    def test_claims_with_uuid_field(self):
        value = uuid.uuid4()
        claims = {"uuid": value}
        key = OctKey.import_key("secret")
        encoded_text = jwt.encode({"alg": "HS256"}, claims, key, encoder_cls=UUIDEncoder)
        token = jwt.decode(encoded_text, key)
        self.assertEqual(token.claims, {"uuid": str(value)})

    def test_validate_list_inclusion(self):
        # Case 1: use option value
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"essential": True, "value": "a"})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"iss": "a"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": "b"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": ["b"]})
        claims_requests.validate({"custom_claim": "a"})
        claims_requests.validate({"custom_claim": ["a"]})

        # Case 2: use option values
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"essential": True, "values": ["a", "b"]})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"iss": "a"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": "c"})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": ["c"]})
        claims_requests.validate({"custom_claim": "a"})
        claims_requests.validate({"custom_claim": "b"})
        claims_requests.validate({"custom_claim": ["a"]})
        claims_requests.validate({"custom_claim": ["b"]})
        claims_requests.validate({"custom_claim": ["a", "b"]})
        claims_requests.validate({"custom_claim": ["c", "a"]})

        # Case 3: do not validate
        claims_requests = jwt.JWTClaimsRegistry()
        claims_requests.validate({"custom_claim": "a"})

        # Case 4: essential claim without value(s)
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"essential": True})
        claims_requests.validate({"custom_claim": "a"})

    def test_validate_allow_blank(self):
        # Case 1: allow blank value
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"essential": True, "allow_blank": True})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"custom_claim": None})
        claims_requests.validate({"custom_claim": ""})
        claims_requests.validate({"custom_claim": []})
        claims_requests.validate({"custom_claim": {}})

        # Case 2: allow blank value without essential
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"allow_blank": True})
        claims_requests.validate({"custom_claim": None})
        claims_requests.validate({"custom_claim": ""})
        claims_requests.validate({"custom_claim": []})
        claims_requests.validate({"custom_claim": {}})

        # Case 3: do not allow blank value
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"essential": True, "allow_blank": False})
        self.assertRaises(MissingClaimError, claims_requests.validate, {"custom_claim": None})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": ""})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": []})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": {}})

        # Case 4: do not allow blank value without essential
        claims_requests = jwt.JWTClaimsRegistry(custom_claim={"allow_blank": False})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": None})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": ""})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": []})
        self.assertRaises(InvalidClaimError, claims_requests.validate, {"custom_claim": {}})
