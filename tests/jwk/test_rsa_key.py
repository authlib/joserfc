from unittest import TestCase
from joserfc.jwk import RSAKey
from tests.keys import read_key


class TestRSAKey(TestCase):
    default_key = RSAKey.generate_key()

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
        key: RSAKey = RSAKey.import_key(data)
        self.assertEqual(key.as_dict(), data)
        self.assertFalse(key.is_private)
        self.assertIsNone(key.private_key)

    def test_with_oth(self):
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
            "oth": "invalid information",
        }
        self.assertRaises(ValueError, RSAKey.import_key, data)

    def test_import_only_from_d(self):
        data = {
            "kty": "RSA",
            "n": (
                "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmd"
                "s2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnila"
                "kGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72Uw"
                "xrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tu"
                "EQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevo"
                "JArm-L5StowjzGy-_bq6Gw"
            ),
            "e": "AQAB",
            "d": (
                "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5Knt"
                "aEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDs"
                "JzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfC"
                "s6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2"
                "Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILS"
                "B3lOW085-4qE3DzgrTjgyQ"
            ),
        }
        key: RSAKey = RSAKey.import_key(data)
        self.assertTrue(key.is_private)
        data["p"] = (
            "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE"
            "9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc"
            "9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM"
        )
        self.assertRaises(ValueError, RSAKey.import_key, data)

    def test_import_key_from_ssh(self):
        ssh_public_pem = read_key("ssh-rsa-public.pem")
        key: RSAKey = RSAKey.import_key(ssh_public_pem)
        self.assertFalse(key.is_private)

        ssh_private_pem = read_key("ssh-rsa-private.pem")
        key: RSAKey = RSAKey.import_key(ssh_private_pem)
        self.assertTrue(key.is_private)

    def test_import_key_from_openssl(self):
        public_pem = read_key("rsa-openssl-public.pem")
        key: RSAKey = RSAKey.import_key(public_pem)
        self.assertFalse(key.is_private)

        private_pem = read_key("rsa-openssl-private.pem")
        key: RSAKey = RSAKey.import_key(private_pem)
        self.assertTrue(key.is_private)

    def test_output_as_methods(self):
        private_pem = read_key("rsa-openssl-private.pem")
        key: RSAKey = RSAKey.import_key(private_pem)

        # as_dict
        data = key.as_dict()
        self.assertIn("d", data)
        data = key.as_dict(private=True)
        self.assertIn("d", data)
        data = key.as_dict(private=False)
        self.assertNotIn("d", data)

        # as_pem
        data = key.as_pem()
        self.assertIn(b"PRIVATE", data)
        data = key.as_pem(private=True)
        self.assertIn(b"PRIVATE", data)
        data = key.as_pem(private=False)
        self.assertIn(b"PUBLIC", data)

        # as_der
        data = key.as_der()
        self.assertIsInstance(data, bytes)

    def test_generate_key(self):
        self.assertRaises(ValueError, RSAKey.generate_key, 8)
        self.assertRaises(ValueError, RSAKey.generate_key, 601)

        key = RSAKey.generate_key(private=False)
        self.assertFalse(key.is_private)
        self.assertIsNone(key.kid)

        key = RSAKey.generate_key(auto_kid=True)
        self.assertIsNotNone(key.kid)

    def test_import_from_der_bytes(self):
        value1 = self.default_key.as_der()
        key1 = RSAKey.import_key(value1)
        self.assertEqual(value1, key1.as_der())

    def test_import_from_certificate(self):
        firebase_cert = read_key("firebase-cert.pem")
        key: RSAKey = RSAKey.import_key(firebase_cert)
        data = key.as_dict()
        self.assertEqual(data["kty"], "RSA")

    def test_output_with_password(self):
        private_pem = read_key("rsa-openssl-private.pem")
        key: RSAKey = RSAKey.import_key(private_pem)
        pem = key.as_pem(password="secret")
        self.assertRaises(TypeError, RSAKey.import_key, pem)
        key2 = RSAKey.import_key(pem, password="secret")
        self.assertEqual(key.as_dict(), key2.as_dict())

    def test_key_eq(self):
        key1 = self.default_key
        key2 = RSAKey.import_key(key1.as_dict())
        self.assertIsNot(key1, key2)
        self.assertEqual(key1, key2)
        key3 = RSAKey.generate_key()
        self.assertNotEqual(key1, key3)
