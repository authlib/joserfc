from joserfc import jwt
from joserfc.jwk import OctKey
from tests.base import TestFixture, load_key


class TestJWTFixtures(TestFixture):
    def run_test(self, data):
        header = data["header"]
        algorithms = [header["alg"]]
        if "secret" in data:
            key = OctKey.import_key(data["secret"])
            private_key = key
            public_key = key
        else:
            private_key = load_key(data["private_key"])
            public_key = load_key(data["public_key"])

        claims = data["payload"]
        value = jwt.encode(header, claims, private_key, algorithms=algorithms)
        if "token" in data:
            self.assertEqual(value, data["token"])

        obj = jwt.decode(value, public_key, algorithms=algorithms)
        self.assertEqual(obj.header["typ"], "JWT")
        self.assertEqual(obj.claims, claims)


TestJWTFixtures.load_fixture("jwt_use_jws.json")
