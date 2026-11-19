import warnings
from unittest import TestCase

from joserfc import jwt
from joserfc.errors import SecurityWarning
from joserfc.jwk import OctKey, RSAKey


def _security_warnings(recorded):
    return [w for w in recorded if issubclass(w.category, SecurityWarning)]


class TestKeySizes(TestCase):
    def test_hmac_warns_below_hash_size(self):
        key = OctKey.import_key(b"a" * 32)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            jwt.encode({"alg": "HS512"}, {"sub": "a"}, key, algorithms=["HS512"])

        warnings_ = _security_warnings(recorded)
        self.assertEqual(len(warnings_), 1)
        self.assertIn("64 bytes for HS512", str(warnings_[0].message))

    def test_hmac_does_not_warn_when_key_is_large_enough(self):
        key = OctKey.import_key(b"a" * 64)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            jwt.encode({"alg": "HS512"}, {"sub": "a"}, key, algorithms=["HS512"])

        self.assertEqual(_security_warnings(recorded), [])

    def test_hmac_warning_is_algorithm_specific(self):
        key = OctKey.import_key(b"a" * 32)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            jwt.encode({"alg": "HS256"}, {"sub": "a"}, key, algorithms=["HS256"])

        self.assertEqual(_security_warnings(recorded), [])

    def test_rsa_warns_below_2048_bits(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            key = RSAKey.generate_key(1024, private=True)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            jwt.encode({"alg": "RS256"}, {"sub": "a"}, key, algorithms=["RS256"])

        warnings_ = _security_warnings(recorded)
        self.assertEqual(len(warnings_), 1)
        self.assertIn("2048 bits for RS256", str(warnings_[0].message))

    def test_rsa_does_not_warn_when_key_is_large_enough(self):
        key = RSAKey.generate_key(2048, private=True)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            jwt.encode({"alg": "RS256"}, {"sub": "a"}, key, algorithms=["RS256"])

        self.assertEqual(_security_warnings(recorded), [])
