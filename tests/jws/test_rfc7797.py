from joserfc.jwk import OctKey
from joserfc.errors import (
    DecodeError,
    MissingAlgorithmError,
    BadSignatureError,
    InvalidHeaderValueError,
    MissingCritHeaderError,
    UnsupportedHeaderError,
)
from joserfc.util import to_bytes
from joserfc.jws import HeaderDict
from joserfc import jws
from tests.base import TestFixture


default_key = OctKey.import_key(
    {"kty": "oct", "k": ("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")}
)


class TestRFC7797(TestFixture):
    def run_test(self, data):
        protected = data["protected"]
        payload = data["payload"]
        value1 = jws.serialize_compact(protected, payload, default_key)
        self.assertEqual(value1, data["compact"])
        obj1 = jws.deserialize_compact(value1, default_key, payload=payload)
        self.assertEqual(obj1.headers(), protected)
        self.assertEqual(obj1.payload, to_bytes(payload))
        value2 = jws.serialize_json({"protected": protected}, payload, default_key)
        self.assertEqual(value2, data["flattened_json"])
        obj2 = jws.deserialize_json(value2, default_key)
        self.assertTrue(obj2.flattened)
        self.assertEqual(obj2.payload, to_bytes(payload))
        self.assertEqual(obj2.members[0].protected, protected)

    def test_b64_without_crit(self):
        protected = {"alg": "HS256", "b64": False}
        self.assertRaises(MissingCritHeaderError, jws.serialize_compact, protected, "i", default_key)

    def test_invalid_b64_value(self):
        protected = {"alg": "HS256", "b64": "true", "crit": ["b64"]}
        self.assertRaises(InvalidHeaderValueError, jws.serialize_compact, protected, "i", default_key)

    def test_compact_invalid_value_length(self):
        self.assertRaises(DecodeError, jws.deserialize_compact, b"a.b.c.d.e", default_key)

    def test_invalid_header(self):
        self.assertRaises(DecodeError, jws.deserialize_compact, b"a.b.c", default_key)

    def test_compact_missing_alg(self):
        self.assertRaises(MissingAlgorithmError, jws.deserialize_compact, b"e30.a.b", default_key)

    def test_compact_bad_signature(self):
        protected = {"alg": "HS256", "b64": False, "crit": ["b64"]}
        value = jws.serialize_compact(protected, "hello", default_key)
        key2 = OctKey.import_key("secret")
        self.assertRaises(BadSignatureError, jws.deserialize_compact, value, key2)

    def test_compact_use_registry(self):
        protected = {"alg": "HS256", "b64": True, "crit": ["b64"]}
        value = jws.serialize_compact(protected, "hello", default_key)
        obj = jws.deserialize_compact(value, default_key)
        self.assertEqual(obj.protected, protected)

        protected = {"alg": "HS256"}
        value = jws.serialize_compact(protected, "hello", default_key)
        obj = jws.deserialize_compact(value, default_key)
        self.assertEqual(obj.protected, protected)

    def test_json_without_protected_header(self):
        header = {"alg": "HS256", "b64": False, "crit": ["b64"]}
        member: HeaderDict = {"header": header}
        self.assertRaises(UnsupportedHeaderError, jws.serialize_json, member, "hello", default_key)

    def test_general_json(self):
        member: HeaderDict = {"protected": {"alg": "HS256"}}
        value = jws.serialize_json([member], "hello", default_key)
        obj = jws.deserialize_json(value, default_key)
        self.assertFalse(obj.flattened)

    def test_json_bad_signature(self):
        member: HeaderDict = {"protected": {"alg": "HS256", "b64": False, "crit": ["b64"]}}
        value = jws.serialize_json(member, "hello", default_key)
        key2 = OctKey.import_key("secret")
        self.assertRaises(BadSignatureError, jws.deserialize_json, value, key2)


TestRFC7797.load_fixture("jws_rfc7797.json")
