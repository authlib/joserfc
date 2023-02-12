import json
from unittest import TestCase
from pathlib import Path
from joserfc.jws import serialize_compact, deserialize_compact
from joserfc.jwk import Key, OctKey, RSAKey, ECKey
from ..util import read_key

CASES_PATH = Path(__file__).parent / "fixtures"


def read_fixture(filename: str):
    filepath = (CASES_PATH / filename).resolve()

    with open(filepath) as f:
        data = json.load(f)
    return data


class TestCompact(TestCase):
    @classmethod
    def load_fixture(cls, filename: str, private_key, public_key):
        data = read_fixture(filename)
        payload = data['payload'].encode('utf-8')

        for case in data['cases']:
            cls.attach_case(payload, case, private_key, public_key)

    @classmethod
    def attach_case(cls, payload: bytes, case, private_key, public_key):
        alg = case['alg']
        if 'value' in case:
            expect = case['value'].encode('utf-8')
        else:
            expect = None

        def method(self):
            self.run_compact(alg, payload, expect, private_key, public_key)

        name = 'test_{}'.format(alg)
        method.__name__ = name
        method.__doc__ = f'Run fixture {alg}'
        setattr(cls, name, method)

    def run_compact(self, alg: str, payload: bytes, expect, private_key, public_key):
        header = {'alg': alg}
        value = serialize_compact(header, payload, private_key, [alg])

        if expect:
            self.assertEqual(value, expect)

        obj = deserialize_compact(value, public_key, [alg])
        self.assertEqual(obj.payload, payload)


def add_oct_tests():
    oct_key = OctKey.import_key('rfc')
    TestCompact.load_fixture('jws_oct.json', oct_key, oct_key)


def add_rsa_tests():
    private_key = RSAKey.import_key(read_key("openssl-rsa-private.pem"))
    public_key = RSAKey.import_key(read_key("openssl-rsa-public.pem"))
    TestCompact.load_fixture('jws_rsa.json', private_key, public_key)


def add_ec_tests():
    ec_data = read_fixture('jws_ec.json')
    payload = ec_data['payload'].encode('utf-8')

    for case in ec_data['cases']:
        key = case['key']
        private_key = ECKey.import_key(read_key(f'ec-{key}-private.pem'))
        public_key = ECKey.import_key(read_key(f'ec-{key}-public.pem'))
        TestCompact.attach_case(payload, case, private_key, public_key)


add_oct_tests()
add_rsa_tests()
add_ec_tests()
