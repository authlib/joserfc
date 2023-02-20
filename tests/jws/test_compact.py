from joserfc.jws import serialize_compact, deserialize_compact
from joserfc.jwk import OctKey, RSAKey, ECKey
from joserfc.util import to_bytes
from tests.fixtures import TestFixture
from tests.util import read_key, read_fixture


class TestCompact(TestFixture):
    def run_test(self, case, private_key, public_key):
        alg = case['alg']

        if 'value' in case:
            expect = to_bytes(case['value'])
        else:
            expect = None

        header = {'alg': alg}
        payload = to_bytes(case['payload'])
        value = serialize_compact(header, payload, private_key, [alg])

        if expect:
            self.assertEqual(value, expect)

        obj = deserialize_compact(value, public_key, [alg])
        self.assertEqual(obj.payload, payload)


def add_oct_tests():
    oct_key = OctKey.import_key('rfc')
    TestCompact.load_fixture('jws_compact_oct.json', oct_key, oct_key)


def add_rsa_tests():
    private_key = RSAKey.import_key(read_key("openssl-rsa-private.pem"))
    public_key = RSAKey.import_key(read_key("openssl-rsa-public.pem"))
    TestCompact.load_fixture('jws_compact_rsa.json', private_key, public_key)


def add_ec_tests():
    fixture = read_fixture('jws_compact_ec.json')
    payload = fixture['payload']

    for index, case in enumerate(fixture['cases']):
        key = case['key']
        case['payload'] = payload
        case['id'] = f'EC_{key}_{index}'
        private_key = ECKey.import_key(read_key(f'ec-{key}-private.pem'))
        public_key = ECKey.import_key(read_key(f'ec-{key}-public.pem'))
        TestCompact.attach_case(case, private_key, public_key)


add_oct_tests()
add_rsa_tests()
add_ec_tests()
