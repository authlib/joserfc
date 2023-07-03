from tests.base import TestFixture, load_key
from joserfc import jws
from joserfc.util import urlsafe_b64encode


# https://datatracker.ietf.org/doc/html/rfc7520#section-4
payload = (
    b"It\xe2\x80\x99s a dangerous business, Frodo, going out your door. "
    b"You step onto the road, and if you don't keep your feet, "
    b"there\xe2\x80\x99s no knowing where you might be swept off to."
)
b64_payload = urlsafe_b64encode(payload).decode("utf-8")


class TestJWSRFC7520(TestFixture):
    def run_test(self, data):
        private_key = load_key(data["private_key"])
        public_key = load_key(data["public_key"])

        protected = data["protected"]
        algorithms = [protected["alg"]]

        obj1 = jws.deserialize_compact(data["compact"], public_key, algorithms=algorithms)
        self.assertEqual(obj1.payload, payload)

        obj2 = jws.deserialize_json(data["general_json"], public_key, algorithms=algorithms)
        self.assertEqual(obj2.payload, payload)
        self.assertEqual(obj2.flattened, False)

        obj3 = jws.deserialize_json(data["flattened_json"], public_key, algorithms=algorithms)
        self.assertEqual(obj3.payload, payload)
        self.assertEqual(obj3.flattened, True)

        # try serialize and deserialize pair
        value4 = jws.serialize_compact(protected, payload, private_key, algorithms=algorithms)
        obj4 = jws.deserialize_compact(value4, public_key, algorithms=algorithms)
        self.assertEqual(obj4.payload, payload)

        member = {"protected": protected}
        value5 = jws.serialize_json([member], payload, private_key, algorithms=algorithms)
        obj5 = jws.deserialize_json(value5, public_key, algorithms=algorithms)
        self.assertEqual(obj5.payload, payload)
        self.assertEqual(obj5.flattened, False)

        value6 = jws.serialize_json(member, payload, private_key, algorithms=algorithms)
        obj6 = jws.deserialize_json(value6, public_key, algorithms=algorithms)
        self.assertEqual(obj6.payload, payload)
        self.assertEqual(obj6.flattened, True)

        # signature won't change with these algorithms
        if protected["alg"].startswith(("HS", "RS")):
            self.assertEqual(value4, data["compact"])
            self.assertEqual(value5, data["general_json"])
            self.assertEqual(value6, data["flattened_json"])

    def test_signature_with_detached_content(self):
        # https://datatracker.ietf.org/doc/html/rfc7520#section-4.5
        protected = {
            "alg": "HS256",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
        }
        key = load_key("RFC7520-oct-sig.json")
        value1 = jws.serialize_compact(protected, payload, key)
        compact_result = (
            "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW"
            "VlZjMxNGJjNzAzNyJ9"
            ".."
            "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
        )
        self.assertEqual(jws.detach_content(value1), compact_result)

        member = {"protected": protected}
        value2 = jws.serialize_json([member], payload, key)
        general_json = {
            "signatures": [
                {
                    "protected": (
                        "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcx"
                        "Yi1iZmQ2LWVlZjMxNGJjNzAzNyJ9"
                    ),
                    "signature": "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
                }
            ]
        }
        self.assertEqual(jws.detach_content(value2), general_json)

        flattened_json = {
            "protected": (
                "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcx"
                "Yi1iZmQ2LWVlZjMxNGJjNzAzNyJ9"
            ),
            "signature": "s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0"
        }
        value3 = jws.serialize_json(member, payload, key)
        self.assertEqual(jws.detach_content(value3), flattened_json)

    def test_protecting_specific_header_fields(self):
        # https://datatracker.ietf.org/doc/html/rfc7520#section-4.6
        protected = {"alg": "HS256"}
        unprotected = {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"}
        member = {"protected": protected, "header": unprotected}
        key = load_key("RFC7520-oct-sig.json")

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
        self.assertEqual(value1, general_json)

        value2 = jws.serialize_json(member, payload, key)
        flattened_json = {
            "payload": b64_payload,
            "protected": "eyJhbGciOiJIUzI1NiJ9",
            "header": {"kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"},
            "signature": "bWUSVaxorn7bEF1djytBd0kHv70Ly5pvbomzMWSOr20"
        }
        self.assertEqual(value2, flattened_json)

    def test_protecting_content_only(self):
        # https://datatracker.ietf.org/doc/html/rfc7520#section-4.7
        unprotected = {
            "alg": "HS256",
            "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
        }
        key = load_key("RFC7520-oct-sig.json")
        member = {"header": unprotected}
        value1 = jws.serialize_json([member], payload, key)
        general_json = {
            "payload": b64_payload,
            "signatures": [
                {
                    "header": {
                        "alg": "HS256",
                        "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
                    },
                    "signature": "xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"
                }
            ]
        }
        self.assertEqual(value1, general_json)

        value2 = jws.serialize_json(member, payload, key)
        flattened_json = {
            "payload": b64_payload,
            "header": {
                "alg": "HS256",
                "kid": "018c0ae5-4d9b-471b-bfd6-eef314bc7037"
            },
            "signature": "xuLifqLGiblpv9zBpuZczWhNj1gARaLV3UxvxhJxZuk"
        }
        self.assertEqual(value2, flattened_json)


TestJWSRFC7520.load_fixture("jws_rfc7520.json")
