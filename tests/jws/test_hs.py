from unittest import TestCase
from joserfc.jws import serialize_compact, deserialize_compact
from joserfc.jwk import OctKey


class TestHS(TestCase):
    key = OctKey.import_key('rfc')

    def run_compact(self, alg: str, expect: bytes):
        header = {'alg': alg}
        payload = b'hello'
        value = serialize_compact(header, payload, self.key, [alg])
        self.assertEqual(value, expect)

        obj = deserialize_compact(expect, self.key, [alg])
        self.assertEqual(obj.payload, payload)

    def test_compact_HS256(self):
        expect = (
            b'eyJhbGciOiJIUzI1NiJ9.aGVsbG8.'
            b'92P-6BQfptptqR5ESrsFD2Zv31kczcmHOR6eQXIaxVE'
        )
        self.run_compact('HS256', expect)

    def test_compact_HS384(self):
        expect = (
            b'eyJhbGciOiJIUzM4NCJ9.aGVsbG8.'
            b'LIiSePQNBOB6KwvO6EWcnfF6QC2lkijalXBokVRzNSltOmTSI3ujNBPqADnMaTvb'
        )
        self.run_compact('HS384', expect)

    def test_compact_HS512(self):
        expect = (
            b'eyJhbGciOiJIUzUxMiJ9.aGVsbG8.'
            b'QN5Ic-wF0VAKSpTjIlSqxYSS0Th6hiiDRoBVjqOweUmYsqZ5qM8jIez77l1rXx'
            b'LycyWqrhzfwVvwrAdCBzCm1Q'
        )
        self.run_compact('HS512', expect)
