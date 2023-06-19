from joserfc import jwt
from joserfc.jwk import RSAKey
from tests.fixtures import TestFixture
from tests.util import read_key


class TestJWTFixtures(TestFixture):
    def run_test(self, case, private_key, public_key):
        alg = case['alg']

        if 'value' in case:
            expect = case['value']
        else:
            expect = None

        header = {'alg': alg}
        claims = case['payload']
        registry = jwt.JWTRegistry(algorithms=[alg])
        value = jwt.encode(header, claims, private_key, registry)

        if expect:
            self.assertEqual(value, expect)

        obj = jwt.decode(value, public_key, registry)
        self.assertEqual(obj.claims, claims)


def add_rsa_tests():
    private_key = RSAKey.import_key(read_key("openssl-rsa-private.pem"))
    public_key = RSAKey.import_key(read_key("openssl-rsa-public.pem"))
    TestJWTFixtures.load_fixture('jwt_rsa.json', private_key, public_key)

add_rsa_tests()

TestJWTFixtures.load_fixture('jwt_oct.json', b'secret', b'secret')