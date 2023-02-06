from unittest import TestCase
from joserfc.jwk import OctKey


class TestOctKey(TestCase):
    def test_import_key_from_str(self):
        key = OctKey.import_key('rfc')
        self.assertEqual(key['k'], 'cmZj')
