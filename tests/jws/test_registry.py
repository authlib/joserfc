import unittest

from joserfc.jws import JWSRegistry
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey


class JWSRegistryTest(unittest.TestCase):
    oct_key = OctKey.generate_key()
    rsa_key = RSAKey.generate_key()
    ec_key = ECKey.generate_key()
    okp_key = OKPKey.generate_key()

    def test_guess_recommended_algorithm(self):
        name = JWSRegistry.guess_alg(self.oct_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(name, "HS256")

        name = JWSRegistry.guess_alg(self.rsa_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(name, "RS256")

        name = JWSRegistry.guess_alg(self.ec_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(name, "ES256")

        name = JWSRegistry.guess_alg(self.okp_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(name, None)

    def test_guess_security_algorithm(self):
        name = JWSRegistry.guess_alg(self.oct_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "HS512")

        name = JWSRegistry.guess_alg(self.rsa_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "RS512")

        name = JWSRegistry.guess_alg(self.ec_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "ES256")

        ec521 = ECKey.generate_key("P-521")
        name = JWSRegistry.guess_alg(ec521, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "ES512")

        name = JWSRegistry.guess_alg(self.okp_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "EdDSA")
