from unittest import TestCase
from joserfc.jwk import OctKey
from ..util import read_key


class TestOctKey(TestCase):
    def test_import_key_from_str(self):
        key = OctKey.import_key('rfc')
        self.assertEqual(key['k'], 'cmZj')

    def test_import_key_from_bytes(self):
        key = OctKey.import_key(b'rfc')
        self.assertEqual(key['k'], 'cmZj')

    def test_import_key_from_dict(self):
        # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.3
        data = {
            "kty": "oct",
            "alg": "A128KW",
            "k": "GawgguFyGrWKav7AX4VKUg",
        }
        key = OctKey.import_key(data)
        self.assertEqual(key.as_dict(), data)

    def test_import_pem_key(self):
        public_pem = read_key("ec-p256-public.pem")
        self.assertRaises(ValueError, OctKey.import_key, public_pem)

    def test_generate_key(self):
        key = OctKey.generate_key()
        self.assertEqual(len(key.raw_key), 32)

        self.assertRaises(ValueError, OctKey.generate_key, private=False)
        self.assertRaises(ValueError, OctKey.generate_key, 251)
