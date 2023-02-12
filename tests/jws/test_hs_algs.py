from unittest import TestCase
from joserfc.jws import serialize_compact, deserialize_compact
from joserfc.jwk import OctKey


class TestHS(TestCase):
    key = OctKey.import_key('rfc')

    def test_serialize_compact_hs256(self):
        header = {'alg': 'HS256'}
        payload = b'hello'
        value = serialize_compact(header, payload, self.key)
        expect = (
            b'eyJhbGciOiJIUzI1NiJ9'
            b'.aGVsbG8'
            b'.92P-6BQfptptqR5ESrsFD2Zv31kczcmHOR6eQXIaxVE'
        )
        self.assertEqual(value, expect)
