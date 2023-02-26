from unittest import TestCase
from joserfc.jwk import RSAKey
from ..util import read_key


class TestRSAKey(TestCase):
    def test_import_key_from_dict(self):
        # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
        data = {
            "kty": "RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86"
                "zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5"
                "JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ"
                "MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
                "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4"
                "4-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29",
        }
        key = RSAKey.import_key(data)
        self.assertEqual(key.as_dict(), data)
        self.assertEqual(key.is_private, False)

    def test_import_key_from_ssh(self):
        ssh_public_pem = read_key("ssh-rsa-public.pem")
        key = RSAKey.import_key(ssh_public_pem)
        self.assertEqual(key.is_private, False)

    def test_import_key_from_openssl(self):
        public_pem = read_key("openssl-rsa-public.pem")
        key = RSAKey.import_key(public_pem)
        self.assertEqual(key.is_private, False)

        private_pem = read_key("openssl-rsa-private.pem")
        key = RSAKey.import_key(private_pem)
        self.assertEqual(key.is_private, True)

    def test_as_dict(self):
        private_pem = read_key("openssl-rsa-private.pem")
        key = RSAKey.import_key(private_pem)
        data = key.as_dict()
        self.assertIn('d', data)
        data = key.as_dict(private=False)
        self.assertNotIn('d', data)
