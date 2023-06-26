from tests.keys import load_key
from tests.fixtures import TestFixture, read_fixture
from joserfc import jws
from joserfc.util import to_bytes, urlsafe_b64encode


# https://datatracker.ietf.org/doc/html/rfc7520#section-4
payload = (
    b"It\xe2\x80\x99s a dangerous business, Frodo, going out your door. "
    b"You step onto the road, and if you don't keep your feet, "
    b"there\xe2\x80\x99s no knowing where you might be swept off to."
)


class TestJWS(TestFixture):
    def run_test(self, data, private_key, public_key):
        protected = data["protected"]
        algorithms = [protected["alg"]]

        obj1 = jws.deserialize_compact(data["compact"], public_key, algorithms=algorithms)
        self.assertEqual(obj1.payload, payload)

        obj2 = jws.deserialize_json(data["general_json"], public_key, algorithms=algorithms)
        self.assertEqual(obj2.payload, payload)
        self.assertEqual(obj2.flatten, False)

        obj3 = jws.deserialize_json(data["flattened_json"], public_key, algorithms=algorithms)
        self.assertEqual(obj3.payload, payload)
        self.assertEqual(obj3.flatten, True)

        # try serialize and deserialize pair
        value4 = jws.serialize_compact(protected, payload, private_key, algorithms=algorithms)
        obj4 = jws.deserialize_compact(value4, public_key, algorithms=algorithms)
        self.assertEqual(obj4.payload, payload)

        member = {"protected": protected}
        value5 = jws.serialize_json([member], payload, private_key, algorithms=algorithms)
        obj5 = jws.deserialize_json(value5, public_key, algorithms=algorithms)
        self.assertEqual(obj5.payload, payload)
        self.assertEqual(obj5.flatten, False)

        value6 = jws.serialize_json(member, payload, private_key, algorithms=algorithms)
        obj6 = jws.deserialize_json(value6, public_key, algorithms=algorithms)
        self.assertEqual(obj6.payload, payload)
        self.assertEqual(obj6.flatten, True)

        # signature won't change with these algorithms
        if data["id"].startswith(("HS", "RS")):
            self.assertEqual(value4, to_bytes(data["compact"]))
            self.assertEqual(value5, data["general_json"])
            self.assertEqual(value6, data["flattened_json"])

    def test_protecting_specific_header_fields(self):
        # https://datatracker.ietf.org/doc/html/rfc7520#section-4.6
        protected = {"alg": "HS256"}
        unprotected = {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"}
        member = {"protected": protected, "header": unprotected}
        key = load_key("RFC7520-oct-sig.json")
        b64_payload = urlsafe_b64encode(payload).decode("utf-8")

        value1 = jws.serialize_json([member], payload, key)
        general_json = {
            "payload": b64_payload,
            "signatures": [
                {
                    "protected": "eyJhbGciOiJIUzI1NiJ9",
                    "header": {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},
                    "signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"
                }
            ]
        }
        self.assertDictEqual(value1, general_json)

        value2 = jws.serialize_json(member, payload, key)
        flattened_json = {
            "payload": b64_payload,
            "protected": "eyJhbGciOiJIUzI1NiJ9",
            "header": {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},
            "signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"
        }
        self.assertDictEqual(value2, flattened_json)

    def test_protecting_content_only(self):
        # https://datatracker.ietf.org/doc/html/rfc7520#section-4.7
        unprotected = {
            "alg": "HS256",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
        }
        key = load_key("RFC7520-oct-sig.json")
        member = {"header": unprotected}
        value1 = jws.serialize_json([member], payload, key)


def add_jws_tests():
    examples = read_fixture('jws_rfc7520.json')

    for data in examples:
        private_key = load_key(data["private_key"])
        public_key = load_key(data["public_key"])
        TestJWS.attach_case(data, private_key, public_key)


add_jws_tests()
