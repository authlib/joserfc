from unittest import TestCase
from joserfc.jwk import OctKey


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
