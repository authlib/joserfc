import typing as t
from unittest import TestCase
from joserfc import jwt
from joserfc.jwk import OKPKey
from joserfc.errors import InvalidKeyTypeError, InvalidKeyCurveError, BadSignatureError
from tests.base import load_key


class TestEdDSA(TestCase):
    x25519_key = t.cast(OKPKey, load_key("okp-x25519-alice.json"))
    ed25519_key = t.cast(OKPKey, load_key("okp-ed25519-private.json"))
    ed448_key = t.cast(OKPKey, load_key("okp-ed448-private.pem"))

    def test_EdDSA(self):
        algorithms = ["EdDSA"]
        encoded_jwt = jwt.encode({"alg": "EdDSA"}, {}, self.ed25519_key, algorithms=algorithms)
        jwt.decode(encoded_jwt, self.ed25519_key, algorithms=algorithms)
        self.assertRaises(InvalidKeyTypeError, jwt.decode, encoded_jwt, self.x25519_key, algorithms=algorithms)
        self.assertRaises(InvalidKeyTypeError, jwt.encode, {"alg": "EdDSA"}, {}, self.x25519_key, algorithms=algorithms)

    def test_Ed25519(self):
        algorithms = ["Ed25519"]
        encoded_jwt = jwt.encode({"alg": "Ed25519"}, {}, self.ed25519_key, algorithms=algorithms)
        jwt.decode(encoded_jwt, self.ed25519_key, algorithms=algorithms)
        self.assertRaises(
            InvalidKeyCurveError, jwt.encode, {"alg": "Ed25519"}, {}, self.ed448_key, algorithms=algorithms
        )
        self.assertRaises(InvalidKeyCurveError, jwt.decode, encoded_jwt, self.ed448_key, algorithms=algorithms)
        wrong_key = OKPKey.generate_key("Ed25519", private=False)
        self.assertRaises(BadSignatureError, jwt.decode, encoded_jwt, wrong_key, algorithms=algorithms)

    def test_Ed448(self):
        algorithms = ["Ed448"]
        encoded_jwt = jwt.encode({"alg": "Ed448"}, {}, self.ed448_key, algorithms=algorithms)
        jwt.decode(encoded_jwt, self.ed448_key, algorithms=algorithms)
        self.assertRaises(
            InvalidKeyCurveError, jwt.encode, {"alg": "Ed448"}, {}, self.ed25519_key, algorithms=algorithms
        )
        self.assertRaises(InvalidKeyCurveError, jwt.decode, encoded_jwt, self.ed25519_key, algorithms=algorithms)
        wrong_key = OKPKey.generate_key("Ed448", private=False)
        self.assertRaises(BadSignatureError, jwt.decode, encoded_jwt, wrong_key, algorithms=algorithms)
