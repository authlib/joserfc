from joserfc.jwe import encrypt_compact, decrypt_compact
from joserfc.jwk import RSAKey
from unittest import TestCase
from tests.util import read_key


class TestJWECompact(TestCase):
    def test_encrypt_compact(self):
        public_key = RSAKey.import_key(read_key('openssl-rsa-public.pem'))
        protected = {"alg": "RSA-OAEP", "enc": "A256GCM"}
        payload = b'hello'
        result = encrypt_compact(protected, payload, public_key)
        self.assertEqual(result.count(b'.'), 4)

        private_key = RSAKey.import_key(read_key('openssl-rsa-private.pem'))
        obj = decrypt_compact(result, private_key)
        self.assertEqual(obj.payload, payload)
