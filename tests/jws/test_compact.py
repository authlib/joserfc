import json
from unittest import TestCase
from pathlib import Path
from joserfc.jws import serialize_compact, deserialize_compact
from joserfc.jwk import Key, OctKey, RSAKey
from ..util import read_key

CASES_PATH = Path(__file__).parent / "fixtures"


class TestCompact(TestCase):
    @classmethod
    def load_fixture(cls, filename: str, private_key, public_key):
        filepath = (CASES_PATH / filename).resolve()

        with open(filepath) as f:
            data = json.load(f)

        payload = data['payload'].encode('utf-8')

        def attach_case(alg, expect):

            def method(self):
                header = {'alg': alg}
                value = serialize_compact(header, payload, private_key, [alg])
                self.assertEqual(value, expect)

                obj = deserialize_compact(expect, public_key, [alg])
                self.assertEqual(obj.payload, payload)

            name = 'test_{}'.format(alg)
            method.__name__ = name
            method.__doc__ = 'Run fixture {} - {}'.format(filename, alg)
            setattr(cls, name, method)

        for case in data['cases']:
            attach_case(case['alg'], case['value'].encode('utf-8'))


oct_key = OctKey.import_key('rfc')
TestCompact.load_fixture('HS.json', oct_key, oct_key)

private_key = RSAKey.import_key(read_key("openssl-rsa-private.pem"))
public_key = RSAKey.import_key(read_key("openssl-rsa-public.pem"))
TestCompact.load_fixture('RS.json', private_key, public_key)
