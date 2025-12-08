import unittest

from joserfc.jws import JWSRegistry
from joserfc.jwk import OctKey, RSAKey, ECKey, OKPKey, KeySet


class JWSRegistryTest(unittest.TestCase):
    oct_key = OctKey.generate_key()
    rsa_key = RSAKey.generate_key()
    ec_key = ECKey.generate_key()
    okp_key = OKPKey.generate_key()

    def test_guess_recommended_algorithm(self):
        alg = JWSRegistry.guess_algorithm(self.oct_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(alg.name, "HS256")

        alg = JWSRegistry.guess_algorithm(self.rsa_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(alg.name, "RS256")

        alg = JWSRegistry.guess_algorithm(self.ec_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(alg.name, "ES256")

        alg = JWSRegistry.guess_algorithm(self.okp_key, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(alg, None)

    def test_guess_security_algorithm(self):
        alg = JWSRegistry.guess_algorithm(self.oct_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "HS512")

        alg = JWSRegistry.guess_algorithm(self.rsa_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "RS512")

        alg = JWSRegistry.guess_algorithm(self.ec_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "ES256")

        ec521 = ECKey.generate_key("P-521")
        alg = JWSRegistry.guess_algorithm(ec521, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "ES512")

        alg = JWSRegistry.guess_algorithm(self.okp_key, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "EdDSA")

    def test_filter_algorithms_default_names(self):
        all_names = list(JWSRegistry.algorithms.keys())
        explicit = JWSRegistry.filter_algorithms(self.rsa_key, all_names)
        default = JWSRegistry.filter_algorithms(self.rsa_key)
        self.assertEqual(explicit, default)

    def test_filter_algorithms_ed25519(self):
        """Ed25519 keys should only be compatible with EdDSA and Ed25519, not Ed448."""
        ed25519_key = OKPKey.generate_key("Ed25519")
        algs = JWSRegistry.filter_algorithms(ed25519_key)
        names = [alg.name for alg in algs]
        self.assertIn("EdDSA", names)
        self.assertIn("Ed25519", names)
        self.assertNotIn("Ed448", names)

    def test_filter_algorithms_ed448(self):
        """Ed448 keys should only be compatible with EdDSA and Ed448, not Ed25519."""
        ed448_key = OKPKey.generate_key("Ed448")
        algs = JWSRegistry.filter_algorithms(ed448_key)
        names = [alg.name for alg in algs]
        self.assertIn("EdDSA", names)
        self.assertIn("Ed448", names)
        self.assertNotIn("Ed25519", names)

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

    def test_guess_algorithm_with_key_set(self):
        """guess_algorithm should find the best algorithm across all keys in the KeySet."""
        rsa_key = RSAKey.generate_key()
        ec_key = ECKey.generate_key("P-256")
        key_set = KeySet([rsa_key, ec_key])

        # RS256 comes before ES256 in the recommended list
        alg = JWSRegistry.guess_algorithm(key_set, JWSRegistry.Strategy.RECOMMENDED)
        self.assertEqual(alg.name, "RS256")

        # RS512 has the highest algorithm_security (512) among available algorithms
        alg = JWSRegistry.guess_algorithm(key_set, JWSRegistry.Strategy.SECURITY)
        self.assertEqual(alg.name, "RS512")
