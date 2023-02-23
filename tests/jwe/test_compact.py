from joserfc.jwe import encrypt_compact, decrypt_compact, JWERegistry
from joserfc.jwk import RSAKey, ECKey
from joserfc.rfc7518.jwe_encs import JWE_ENC_MODELS
from unittest import TestCase
from tests.util import read_key


class TestJWECompact(TestCase):
    def run_case(self, alg, enc, private_key, public_key):
        protected = {"alg": alg, "enc": enc}
        payload = b'hello'
        algorithms = {"alg": [alg], "enc": [enc]}
        registry = JWERegistry(algorithms=algorithms)
        result = encrypt_compact(
            protected, payload, public_key,
            registry=registry,
        )
        self.assertEqual(result.count(b'.'), 4)

        obj = decrypt_compact(
            result, private_key,
            registry=registry,
        )
        self.assertEqual(obj.payload, payload)

    def run_cases(self, algs, private_key, public_key):
        for alg in algs:
            for enc in JWE_ENC_MODELS:
                self.run_case(alg, enc.name, private_key, public_key)

    def test_with_rsa_key(self):
        private_key = RSAKey.import_key(read_key('openssl-rsa-private.pem'))
        public_key = RSAKey.import_key(read_key('openssl-rsa-public.pem'))
        algs = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256']
        self.run_cases(algs, private_key, public_key)

    def test_with_ec_key(self):
        algs = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
        for size in [256, 384, 512]:
            private_key = ECKey.import_key(read_key(f'ec-p{size}-private.pem'))
            public_key = ECKey.import_key(read_key(f'ec-p{size}-public.pem'))
            self.run_cases(algs, private_key, public_key)
