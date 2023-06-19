from unittest import TestCase
from joserfc.jwe import encrypt_compact, decrypt_compact, JWERegistry
from joserfc.jwk import RSAKey, ECKey, OctKey
from joserfc.rfc7518.jwe_encs import JWE_ENC_MODELS
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

    def test_RSA_alg(self):
        private_key = RSAKey.import_key(read_key('openssl-rsa-private.pem'))
        public_key = RSAKey.import_key(read_key('openssl-rsa-public.pem'))
        algs = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256']
        self.run_cases(algs, private_key, public_key)

    def test_ECDH_ES_alg(self):
        algs = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
        for size in [256, 384, 512]:
            private_key = ECKey.import_key(read_key(f'ec-p{size}-private.pem'))
            public_key = ECKey.import_key(read_key(f'ec-p{size}-public.pem'))
            self.run_cases(algs, private_key, public_key)

    def test_dir_alg(self):
        self.assertRaises(ValueError, encrypt_compact, {"alg": "dir", "enc": "A128GCM"}, b"j", "secret")
        for enc in JWE_ENC_MODELS:
            key = OctKey.generate_key(enc.cek_size)
            self.run_case('dir', enc.name, key, key)

    def test_AESGCM_alg(self):
        for size in [128, 192, 256]:
            key = OctKey.generate_key(size)
            self.run_cases([f"A{size}GCMKW"], key, key)

    def test_PBES2HS_alg(self):
        algs = {
            "PBES2-HS256+A128KW": 128,
            "PBES2-HS384+A192KW": 192,
            "PBES2-HS512+A256KW": 256,
        }
        for alg in algs:
            key = OctKey.generate_key(algs[alg])
            self.run_cases([alg], key, key)
