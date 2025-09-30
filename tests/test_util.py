import binascii
from unittest import TestCase
from joserfc import util


class TestUtil(TestCase):
    def test_to_bytes(self):
        self.assertEqual(util.to_bytes(b"foo"), b"foo")
        self.assertEqual(util.to_bytes("foo"), b"foo")
        self.assertEqual(util.to_bytes(123), b"123")
        self.assertEqual(util.to_bytes([102, 111, 111]), b"foo")

    def test_to_unicode(self):
        self.assertEqual(util.to_str(b"foo"), "foo")
        self.assertEqual(util.to_str("foo"), "foo")

    def test_int_to_base64(self):
        self.assertRaises(ValueError, util.int_to_base64, -1)

    def test_urlsafe_b64decode(self):
        self.assertEqual(util.urlsafe_b64decode(b"_foo123-"), b"\xfd\xfa(\xd7m\xfe")
        self.assertRaises(binascii.Error, util.urlsafe_b64decode, b"+foo123/")
        for c in "RSTUVWXYZabdef":  # A -> QQ==
            self.assertRaises(binascii.Error, util.urlsafe_b64decode, b"Q" + c.encode())
        for c in "FGH":  # AAAAAAAAAAAAAA -> QUFBQUFBQUFBQUFBQUE=
            self.assertRaises(binascii.Error, util.urlsafe_b64decode, b"QUFBQUFBQUFBQUFBQU" + c.encode())
