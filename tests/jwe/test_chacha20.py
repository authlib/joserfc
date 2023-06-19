from unittest import TestCase
from joserfc.jwe import (
    encrypt_compact,
    decrypt_compact,
    JWERegistry
)
from joserfc.jwk import OctKey
from joserfc.drafts.jwe_chacha20 import JWE_ENC_MODELS


class TestChaCha20(TestCase):
    def setUp(self):
        registry = JWERegistry(
            algorithms={
                "alg": ["dir"],
                "enc": ["C20P", "XC20P"],
            }
        )
        for model in JWE_ENC_MODELS:
            registry.algorithms["enc"][model.name] = model
        self.registry = registry

    def run_test_dir(self, enc: str):
        key = OctKey.generate_key(256)
        protected = {"alg": "dir", "enc": enc}
        encrypted_text = encrypt_compact(protected, b'hello', key, self.registry)
        self.assertEqual(encrypted_text.count(b"."), 4)
        obj = decrypt_compact(encrypted_text, key, self.registry)
        self.assertEqual(obj.payload, b'hello')

        key2 = OctKey.generate_key(256)
        self.assertRaises(ValueError, decrypt_compact, encrypted_text, key2, self.registry)

    def test_dir_c20p(self):
        self.run_test_dir("C20P")

    def test_dir_xc20p(self):
        self.run_test_dir("XC20P")
