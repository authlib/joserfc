from joserfc import jwt
from joserfc.jwk import RSAKey
from tests.fixtures import TestFixture
from tests.keys import load_key


class TestJWTFixtures(TestFixture):
    def run_test(self, case, private_key, public_key):
        alg = case['alg']

        if 'value' in case:
            expect = case['value']
        else:
            expect = None

        header = {'alg': alg}
        claims = case['payload']
        value = jwt.encode(header, claims, private_key, algorithms=[alg])

        if expect:
            self.assertEqual(value, expect)

        obj = jwt.decode(value, public_key, algorithms=[alg])
        self.assertEqual(obj.claims, claims)


def add_rsa_tests():
    private_key: RSAKey = load_key("rsa-openssl-private.pem")
    public_key: RSAKey = load_key("rsa-openssl-public.pem")
    TestJWTFixtures.load_fixture('jwt_rsa.json', private_key, public_key)

add_rsa_tests()

TestJWTFixtures.load_fixture('jwt_oct.json', b'secret', b'secret')
