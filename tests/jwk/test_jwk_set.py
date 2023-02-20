from unittest import TestCase
from joserfc.jwk import KeySet, RSAKey, ECKey
from ..util import read_key


class TestKeySet(TestCase):
    def test_generate_and_import_key_set(self):
        jwks1 = KeySet.generate_key_set('RSA', 2048)
        self.assertEqual(len(jwks1.keys), 4)

        jwks1_data = jwks1.as_dict()
        self.assertEqual(list(jwks1_data.keys()), ['keys'])
        for d1 in jwks1_data['keys']:
            self.assertIn('d', d1)

        for d1 in jwks1.as_dict(private=False)['keys']:
            self.assertNotIn('d', d1)

        jwks2 = KeySet.import_key_set(jwks1_data)
        self.assertEqual(len(jwks2.keys), 4)

    def test_generate_key_set_errors(self):
        self.assertRaises(ValueError, KeySet.generate_key_set, 'NOT_FOUND', 2048)

    def test_initialize_key_set(self):
        keys = []
        pem1 = read_key("openssl-rsa-public.pem")
        keys.append(RSAKey.import_key(pem1))
        pem2 = read_key(f"ec-p256-private.pem")
        keys.append(ECKey.import_key(pem2))

        jwks = KeySet(keys)
        for d1 in jwks.as_dict(private=False)['keys']:
            self.assertNotIn('d', d1)

        self.assertRaises(ValueError, jwks.as_dict, private=True)
