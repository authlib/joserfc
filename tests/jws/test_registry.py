import unittest

from joserfc.jws import JWSRegistry
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey, KeySet


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

    def test_filter_algorithms_default_names(self):
        all_names = list(JWSRegistry.algorithms.keys())
        explicit = JWSRegistry.filter_algorithms(self.rsa_key, all_names)
        default = JWSRegistry.filter_algorithms(self.rsa_key)
        self.assertEqual(explicit, default)

    def test_filter_algorithms_with_key_set(self):
        """filter_algorithms should support KeySet and combine algorithms from all keys."""
        rsa_key1 = RSAKey.generate_key()
        rsa_key2 = RSAKey.generate_key()
        ec_key = ECKey.generate_key("P-256")
        key_set = KeySet([rsa_key1, rsa_key2, ec_key])

        algs = JWSRegistry.filter_algorithms(key_set, JWSRegistry.algorithms.keys())
        names = [alg.name for alg in algs]

        self.assertIn("RS256", names)
        self.assertIn("ES256", names)
        self.assertNotIn("ES384", names)
        self.assertEqual(names.count("RS256"), 1)

    def test_guess_alg_with_key_set(self):
        """guess_alg should find the best algorithm across all keys in the KeySet."""
        rsa_key = RSAKey.generate_key()
        ec_key = ECKey.generate_key("P-256")
        key_set = KeySet([rsa_key, ec_key])

        # RS256 comes before ES256 in the recommended list
        name = JWSRegistry.guess_alg(key_set, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(name, "RS256")

        # RS512 has the highest algorithm_security (512) among available algorithms
        name = JWSRegistry.guess_alg(key_set, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(name, "RS512")
