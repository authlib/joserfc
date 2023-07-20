from unittest import TestCase
from joserfc import util


class TestUtil(TestCase):
    def test_to_bytes(self):
        self.assertEqual(util.to_bytes(b'foo'), b'foo')
        self.assertEqual(util.to_bytes('foo'), b'foo')
        self.assertEqual(util.to_bytes(123), b'123')
        self.assertEqual(util.to_bytes([102, 111, 111]), b'foo')

    def test_to_unicode(self):
        self.assertEqual(util.to_str(b'foo'), 'foo')
        self.assertEqual(util.to_str('foo'), 'foo')

    def test_int_to_base64(self):
        self.assertRaises(
            ValueError,
            util.int_to_base64,
            -1
        )

    def test_json_b64encode(self):
        self.assertEqual(util.json_b64encode("{}"), b"e30")
