from joserfc.jws import serialize_json, deserialize_json
from joserfc.jwk import RSAKey, KeySet
from unittest import TestCase
from tests.base import load_key


class TestJSON(TestCase):
    def test_serialize_json(self):
        key: RSAKey = load_key('rsa-openssl-private.pem')

        member = {'protected': {'alg': 'RS256'}}

        # flatten
        value = serialize_json(member, b'hello', key)
        self.assertIn('signature', value)
        self.assertNotIn('signatures', value)

        obj = deserialize_json(value, key)
        self.assertEqual(obj.payload, b'hello')

        # complete
        value = serialize_json([member], b'hello', key)
        self.assertNotIn('signature', value)
        self.assertIn('signatures', value)

        obj = deserialize_json(value, key)
        self.assertEqual(obj.payload, b'hello')

    def test_use_key_set(self):
        key1 = load_key("ec-p256-alice.json", {"kid": "alice"})
        key2 = load_key("ec-p256-bob.json", {"kid": "bob"})
        member = {'protected': {'alg': 'ES256'}}
        value = serialize_json(member, b'hello', KeySet([key1, key2]))
        self.assertIn('header', value)
        self.assertIn('kid', value['header'])
