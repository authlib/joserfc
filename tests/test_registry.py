from unittest import TestCase

from joserfc.registry import HeaderParameter


class TestRegistry(TestCase):
    def test_int_header_value(self):
        p = HeaderParameter("Custom int value", "int")
        p.validate(123)
        self.assertRaises(ValueError, p.validate, "foo")
