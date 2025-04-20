from joserfc.jwk import OctKey
from joserfc.rfc7797 import (
    JWSRegistry,
    serialize_compact,
    deserialize_compact,
    serialize_json,
    deserialize_json,
)
from joserfc.errors import (
    DecodeError,
    MissingAlgorithmError,
    BadSignatureError,
    InvalidHeaderValueError,
)
from joserfc.util import to_bytes
from joserfc import jws
from tests.base import TestFixture


default_key = OctKey.import_key(
    {"kty": "oct", "k": ("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")}
)


class TestRFC7797(TestFixture):
    def run_test(self, data):
        protected = data["protected"]
        payload = data["payload"]
        value1 = serialize_compact(protected, payload, default_key)
        self.assertEqual(value1, data["compact"])
        obj1 = deserialize_compact(value1, default_key, payload=payload)
        self.assertEqual(obj1.headers(), protected)
        self.assertEqual(obj1.payload, to_bytes(payload))
        value2 = serialize_json({"protected": protected}, payload, default_key)
        self.assertEqual(value2, data["flattened_json"])
        obj2 = deserialize_json(value2, default_key)
        self.assertTrue(obj2.flattened)
        self.assertEqual(obj2.payload, to_bytes(payload))
        self.assertEqual(obj2.members[0].protected, protected)

    def test_b64_without_crit(self):
        protected = {"alg": "HS256", "b64": False}
        self.assertRaises(ValueError, serialize_compact, protected, "i", default_key)

    def test_invalid_b64_value(self):
        protected = {"alg": "HS256", "b64": "true", "crit": ["b64"]}
        self.assertRaises(InvalidHeaderValueError, serialize_compact, protected, "i", default_key)

    def test_compact_invalid_value_length(self):
        self.assertRaises(ValueError, deserialize_compact, b"a.b.c.d.e", default_key)

    def test_invalid_header(self):
        self.assertRaises(DecodeError, deserialize_compact, b"a.b.c", default_key)

    def test_compact_missing_alg(self):
        self.assertRaises(MissingAlgorithmError, deserialize_compact, b"e30.a.b", default_key)

    def test_compact_bad_signature(self):
        protected = {"alg": "HS256", "b64": False, "crit": ["b64"]}
        value = serialize_compact(protected, "hello", default_key)
        key2 = OctKey.import_key("secret")
        self.assertRaises(BadSignatureError, deserialize_compact, value, key2)

    def test_compact_use_registry(self):
        registry = JWSRegistry()
        protected = {"alg": "HS256", "b64": True, "crit": ["b64"]}
        value = serialize_compact(protected, "hello", default_key, registry=registry)
        obj = deserialize_compact(value, default_key, registry=registry)
        self.assertEqual(obj.protected, protected)

        protected = {"alg": "HS256"}
        value = serialize_compact(protected, "hello", default_key, registry=registry)
        obj = deserialize_compact(value, default_key, registry=registry)
        self.assertEqual(obj.protected, protected)

    def test_json_without_protected_header(self):
        registry = JWSRegistry()
        header = {"alg": "HS256", "b64": False, "crit": ["b64"]}
        member = {"header": header}
        value = serialize_json(member, "hello", default_key, registry=registry)
        obj = deserialize_json(value, default_key, registry=registry)
        self.assertTrue(obj.flattened)
        self.assertEqual(obj.headers(), header)

    def test_general_json(self):
        members = [{"protected": {"alg": "HS256"}}]
        value = jws.serialize_json(members, "hello", default_key)
        obj = deserialize_json(value, default_key)
        self.assertFalse(obj.flattened)

    def test_json_bad_signature(self):
        member = {"protected": {"alg": "HS256", "b64": False, "crit": ["b64"]}}
        value = serialize_json(member, "hello", default_key)
        key2 = OctKey.import_key("secret")
        self.assertRaises(BadSignatureError, deserialize_json, value, key2)


TestRFC7797.load_fixture("jws_rfc7797.json")
