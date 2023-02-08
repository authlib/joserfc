from unittest import TestCase
from joserfc.jwk import ECKey
from .util import read_key


class TestECKey(TestCase):
    def test_import_p256_key(self):
        public_pem = read_key("ec-p256-public.pem")
        key = ECKey.import_key(public_pem)
        self.assertEqual(key.is_private, False)

        private_pem = read_key("ec-p256-private.pem")
        key = ECKey.import_key(private_pem)
        self.assertEqual(key.is_private, True)
