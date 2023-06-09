from joserfc.jws import JWSRegistry, serialize_compact, deserialize_compact
from joserfc.jwk import OctKey, RSAKey, ECKey, KeySet
from joserfc.errors import BadSignatureError, DecodeError, MissingAlgorithmError
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
        registry = JWSRegistry(algorithms=[alg])
        value = serialize_compact(header, payload, private_key, registry)

        if expect:
            self.assertEqual(value, expect)

        obj = deserialize_compact(value, public_key, registry)
        self.assertEqual(obj.payload, payload)

    def test_registry_is_none(self):
        value = serialize_compact({"alg": "HS256"}, b"foo", "secret")
        expected = b'eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0'
        self.assertEqual(value, expected)

        obj = deserialize_compact(value, "secret")
        self.assertEqual(obj.payload, b"foo")

    def test_bad_signature_error(self):
        value = b'eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0'
        self.assertRaises(BadSignatureError, deserialize_compact, value, "incorrect")

    def test_raise_none_supported_alg(self):
        self.assertRaises(ValueError, serialize_compact, {"alg": "HS512"}, b"foo", "secret")
        self.assertRaises(ValueError, serialize_compact, {"alg": "NOT"}, b"foo", "secret")

    def test_invalid_length(self):
        self.assertRaises(ValueError, deserialize_compact, b'a.b.c.d', "secret")

    def test_no_invalid_header(self):
        # invalid base64
        value = b'abc.Zm9v.0pehoi'
        self.assertRaises(DecodeError, deserialize_compact, value, "secret")

        # no alg value
        value = b'eyJhIjoiYiJ9.Zm9v.0pehoi'
        self.assertRaises(MissingAlgorithmError, deserialize_compact, value, "secret")

    def test_invalid_payload(self):
        value = b'eyJhbGciOiJIUzI1NiJ9.a$b.0pehoi'
        self.assertRaises(DecodeError, deserialize_compact, value, "secret")

    def test_with_key_set(self):
        keys = KeySet([
            OctKey.import_key("a"),
            OctKey.import_key("b"),
            OctKey.import_key("c"),
        ])
        value = serialize_compact({"alg": "HS256"}, b"foo", keys)
        obj = deserialize_compact(value, keys)
        self.assertEqual(obj.payload, b"foo")

    def test_strict_check_header(self):
        header = {"alg": "HS256", "custom": "hi"}
        self.assertRaises(ValueError, serialize_compact, header, b"hi", "secret")

        registry = JWSRegistry(strict_check_header=False)
        serialize_compact(header, b"hi", "secret", registry)


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
