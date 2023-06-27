from joserfc.jws import JWSRegistry, serialize_compact, deserialize_compact
from joserfc.jwk import OctKey, RSAKey, ECKey, KeySet
from joserfc.errors import BadSignatureError, DecodeError, MissingAlgorithmError
from joserfc.util import to_bytes
from tests.fixtures import TestFixture, read_fixture
from tests.keys import load_key


class TestCompact(TestFixture):
    def run_test(self, data, private_key, public_key):
        alg = data['alg']

        if 'value' in data:
            expect = data['value']
        else:
            expect = None

        header = {'alg': alg}
        payload = to_bytes(data['payload'])
        registry = JWSRegistry(algorithms=[alg])
        value = serialize_compact(header, payload, private_key, registry=registry)

        if expect:
            self.assertEqual(value, expect)

        obj = deserialize_compact(value, public_key, registry=registry)
        self.assertEqual(obj.payload, payload)

    def test_registry_is_none(self):
        value = serialize_compact({"alg": "HS256"}, b"foo", "secret")
        expected = 'eyJhbGciOiJIUzI1NiJ9.Zm9v.0pehoi-RMZM1jl-4TP_C4Y6BJ-bcmsuzfDyQpkpJkh0'
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
        serialize_compact(header, b"hi", "secret", registry=registry)


def add_oct_tests():
    oct_key = OctKey.import_key('rfc')
    TestCompact.load_fixture('jws_compact_oct.json', oct_key, oct_key)


def add_rsa_tests():
    private_key: RSAKey = load_key("rsa-openssl-private.pem")
    public_key: RSAKey = load_key("rsa-openssl-public.pem")
    TestCompact.load_fixture('jws_compact_rsa.json', private_key, public_key)


def add_ec_tests():
    fixture = read_fixture('jws_compact_ec.json')
    payload = fixture['payload']

    for index, data in enumerate(fixture['cases']):
        key = data['key']
        data['payload'] = payload
        data['id'] = f'EC_{key}_{index}'
        private_key: ECKey = load_key(f'ec-{key}-private.pem')
        public_key: ECKey = load_key(f'ec-{key}-public.pem')
        TestCompact.attach_case(data, private_key, public_key)


def add_okp_tests():
    private_key1 = load_key("okp-ed448-private.pem")
    public_key1 = load_key("okp-ed448-public.pem")
    private_key2 = load_key("okp-ed25519-private.json")
    public_key2 = load_key("okp-ed25519-public.json")
    TestCompact.attach_case(
        {"payload": "hello", "alg": "EdDSA", "id": "OKP_ed448"},
        private_key1, public_key1
    )
    TestCompact.attach_case(
        {"payload": "hello", "alg": "EdDSA", "id": "OKP_ed25519"},
        private_key2, public_key2
    )

add_oct_tests()
add_rsa_tests()
add_ec_tests()
add_okp_tests()
