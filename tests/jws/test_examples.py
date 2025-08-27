from tests.base import TestFixture, load_key
from joserfc.jwk import OctKey
from joserfc.jws import HeaderDict
from joserfc import jws


class TestJWSExamples(TestFixture):
    def run_test(self, data):
        if "secret" in data:
            key = OctKey.import_key(data["secret"])
            private_key = key
            public_key = key
        else:
            private_key = load_key(data["private_key"])
            public_key = load_key(data["public_key"])

        protected = data["protected"]
        payload = data["payload"]
        algorithms = [protected["alg"]]

        value1 = jws.serialize_compact(protected, payload, private_key, algorithms=algorithms)
        obj1 = jws.deserialize_compact(value1, public_key, algorithms=algorithms)
        self.assertEqual(obj1.protected, protected)
        if "compact" in data:
            self.assertEqual(value1, data["compact"])

        member: HeaderDict = {"protected": protected}
        value2 = jws.serialize_json(member, payload, private_key, algorithms=algorithms)
        obj2 = jws.deserialize_json(value2, public_key, algorithms=algorithms)
        self.assertTrue(obj2.flattened)
        if "flattened_json" in data:
            self.assertEqual(value2, data["flattened_json"])

        value3 = jws.serialize_json([member], payload, private_key, algorithms=algorithms)
        obj3 = jws.deserialize_json(value3, public_key, algorithms=algorithms)
        self.assertFalse(obj3.flattened)
        if "general_json" in data:
            self.assertEqual(value3, data["general_json"])


TestJWSExamples.load_fixture("jws_examples.json")
