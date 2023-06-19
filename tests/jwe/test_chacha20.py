from unittest import TestCase
from joserfc.jwe import (
    encrypt_compact,
    decrypt_compact,
    JWERegistry,
    EncryptionData,
)
from joserfc.jwk import OctKey
from joserfc.drafts.jwe_chacha20 import JWE_ENC_MODELS, XC20P


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

    def test_xc20p_content_encryption_decryption(self):
        # https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
        payload = bytes.fromhex(
            '4c616469657320616e642047656e746c656d656e206f662074686520636c6173' +
            '73206f66202739393a204966204920636f756c64206f6666657220796f75206f' +
            '6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73' +
            '637265656e20776f756c642062652069742e'
        )

        obj = EncryptionData({}, payload)
        obj.cek = bytes.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
        aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
        obj.encoded["aad"] = aad
        iv = bytes.fromhex('404142434445464748494a4b4c4d4e4f5051525354555657')
        obj.decoded["iv"] = iv

        ciphertext = XC20P.encrypt(obj)
        self.assertEqual(
            ciphertext,
            bytes.fromhex(
                'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb' +
                '731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452' +
                '2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9' +
                '21f9664c97637da9768812f615c68b13b52e'
            )
        )

        tag = obj.decoded["tag"]
        self.assertEqual(tag, bytes.fromhex('c0875924c1c7987947deafd8780acf49'))

        obj.decoded["ciphertext"] = ciphertext
        plaintext = XC20P.decrypt(obj)
        self.assertEqual(plaintext, payload)
