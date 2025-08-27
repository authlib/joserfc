from unittest import TestCase
from joserfc.jwe import (
    JWERegistry,
    GeneralJSONEncryption,
    GeneralJSONSerialization,
    encrypt_compact,
    decrypt_compact,
    encrypt_json,
    decrypt_json,
)
from joserfc.jwa import JWE_ENC_MODELS
from joserfc.jwk import KeySet
from joserfc.errors import InvalidEncryptionAlgorithmError
from joserfc.drafts.jwe_ecdh_1pu import JWE_ALG_MODELS, register_ecdh_1pu
from tests.base import TestFixture, load_key

register_ecdh_1pu()
ecdh_registry = JWERegistry(algorithms=[m.name for m in JWE_ALG_MODELS] + [enc.name for enc in JWE_ENC_MODELS])


class TestECDH1PUCompact(TestFixture):
    def run_test(self, data):
        alice_key = load_key("ec-p256-alice.json")
        bob_key = load_key("ec-p256-bob.json")
        value: str = data["value"]
        payload = data["payload"].encode("utf-8")
        obj = decrypt_compact(
            value.encode("utf-8"),
            private_key=bob_key,
            registry=ecdh_registry,
            sender_key=alice_key,
        )
        self.assertEqual(obj.protected["alg"], data["alg"])
        self.assertEqual(obj.protected["enc"], data["enc"])
        self.assertEqual(obj.plaintext, payload)

    def run_compact_case(self, alg: str, enc: str, recipient_key, sender_key):
        protected = {"alg": alg, "enc": enc}
        value = encrypt_compact(
            protected,
            b"hello",
            public_key=recipient_key,
            registry=ecdh_registry,
            sender_key=sender_key,
        )
        self.assertEqual(value.count("."), 4)
        obj = decrypt_compact(
            value,
            private_key=recipient_key,
            registry=ecdh_registry,
            sender_key=sender_key,
        )
        self.assertEqual(obj.plaintext, b"hello")

    def test_ecdh_1pu_compact_direct_mode(self):
        alice_key = load_key("ec-p256-alice.json")
        bob_key = load_key("ec-p256-bob.json")

        for enc in JWE_ENC_MODELS:
            self.run_compact_case("ECDH-1PU", enc.name, bob_key, alice_key)

        alice_key = load_key("okp-x25519-alice.json")
        bob_key = load_key("okp-x25519-bob.json")
        for enc in JWE_ENC_MODELS:
            self.run_compact_case("ECDH-1PU", enc.name, bob_key, alice_key)

    def test_ecdh_1pu_compact_agreement_mode(self):
        allowed_alg_values = [
            "ECDH-1PU+A128KW",
            "ECDH-1PU+A192KW",
            "ECDH-1PU+A256KW",
        ]
        allowed_enc_values = [
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
        ]

        alice_key = load_key("ec-p256-alice.json")
        bob_key = load_key("ec-p256-bob.json")
        for alg in allowed_alg_values:
            for enc in allowed_enc_values:
                self.run_compact_case(alg, enc, bob_key, alice_key)

        alice_key = load_key("okp-x25519-alice.json")
        bob_key = load_key("okp-x25519-bob.json")
        for alg in allowed_alg_values:
            for enc in allowed_enc_values:
                self.run_compact_case(alg, enc, bob_key, alice_key)

    def test_ecdh_1pu_agreement_mode_with_other_encryption_algorithms(self):
        alice_key = load_key("ec-p256-alice.json")
        bob_key = load_key("ec-p256-bob.json")
        alg_values = [
            "ECDH-1PU+A128KW",
            "ECDH-1PU+A192KW",
            "ECDH-1PU+A256KW",
        ]
        other_enc_values = [
            "A128GCM",
            "A192GCM",
            "A256GCM",
        ]
        for alg in alg_values:
            for enc in other_enc_values:
                protected = {"alg": alg, "enc": enc}
                self.assertRaises(
                    InvalidEncryptionAlgorithmError,
                    encrypt_compact,
                    protected,
                    b"hello",
                    public_key=bob_key,
                    registry=ecdh_registry,
                    sender_key=alice_key,
                )

    def test_load_sender_key_via_skid(self):
        alice_key = load_key("ec-p256-alice.json", {"kid": "alice"})
        bob_key = load_key("ec-p256-bob.json", {"kid": "bob"})
        key = KeySet([alice_key, bob_key])

        protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256", "kid": "bob", "skid": "alice"}
        value = encrypt_compact(
            protected,
            b"hello",
            public_key=key,
            registry=ecdh_registry,
            sender_key=key,
        )
        self.assertEqual(value.count("."), 4)
        obj = decrypt_compact(
            value,
            private_key=key,
            registry=ecdh_registry,
            sender_key=key,
        )
        self.assertEqual(obj.plaintext, b"hello")

    def test_sender_key_not_found_via_kid(self):
        alice_key = load_key("ec-p256-alice.json", {"kid": "alice"})
        bob_key = load_key("ec-p256-bob.json", {"kid": "bob"})
        protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}
        value = encrypt_compact(
            protected,
            b"hello",
            public_key=bob_key,
            registry=ecdh_registry,
            sender_key=alice_key,
        )
        key_set = KeySet([alice_key, bob_key])
        self.assertRaises(
            ValueError,
            decrypt_compact,
            value,
            private_key=bob_key,
            registry=ecdh_registry,
            sender_key=key_set,
        )

    def test_sender_key_not_found_via_alg(self):
        alice_key = load_key("ec-p256-alice.json", {"kid": "alice"})
        protected = {"alg": "ECDH-1PU+A128KW", "enc": "A128CBC-HS256"}
        bob_key = load_key("RFC7520-RSA-private.json")
        key_set = KeySet([bob_key])
        self.assertRaises(
            ValueError,
            encrypt_compact,
            protected,
            b"hello",
            public_key=alice_key,
            registry=ecdh_registry,
            sender_key=key_set,
        )


TestECDH1PUCompact.load_fixture("jwe_compact_ecdh_1pu.json")


class TestECDH1PUJSON(TestCase):
    def test_example_B(self):
        # https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B.11
        result: GeneralJSONSerialization = {
            "protected": (
                "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi"
                "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L"
                "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB"
                "RnFVQUZhMzlkeUJjIn19"
            ),
            "unprotected": {"jku": "https://alice.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"kid": "bob-key-2"},
                    "encrypted_key": (
                        "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CH"
                        "JQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    ),
                },
                {
                    "header": {"kid": "2021-05-06"},
                    "encrypted_key": (
                        "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCq"
                        "RpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    ),
                },
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ",
        }
        alice_key = load_key("okp-x25519-alice.json")
        bob_key = load_key("okp-x25519-bob.json", {"kid": "bob-key-2"})
        charlie_key = load_key("okp-x25519-charlie.json", {"kid": "2021-05-06"})
        protected = {
            "alg": "ECDH-1PU+A128KW",
            "enc": "A256CBC-HS512",
            "apu": "QWxpY2U",
            "apv": "Qm9iIGFuZCBDaGFybGll",
            "epk": {"kty": "OKP", "crv": "X25519", "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"},
        }
        obj = decrypt_json(
            result,
            KeySet([bob_key, charlie_key]),
            registry=ecdh_registry,
            sender_key=alice_key,
        )
        self.assertEqual(obj.protected, protected)
        value1 = encrypt_json(obj, KeySet([bob_key, charlie_key]), registry=ecdh_registry, sender_key=alice_key)
        self.assertEqual(value1["protected"], result["protected"])

    def test_with_key_set(self):
        alice_key = load_key("okp-x25519-alice.json", {"kid": "alice"})
        bob_key = load_key("okp-x25519-bob.json", {"kid": "bob"})
        charlie_key = load_key("okp-x25519-charlie.json", {"kid": "charlie"})
        keys = KeySet([alice_key, bob_key, charlie_key])

        obj = GeneralJSONEncryption(
            {"enc": "A128CBC-HS256"},
            plaintext=b"hello",
            aad=b"world",
        )
        obj.add_recipient({"alg": "ECDH-1PU+A128KW", "kid": "alice", "skid": "charlie"})
        obj.add_recipient({"alg": "ECDH-1PU+A256KW", "kid": "bob"})
        value = encrypt_json(obj, keys, registry=ecdh_registry, sender_key=keys)
        obj1 = decrypt_json(value, keys, registry=ecdh_registry, sender_key=keys)
        self.assertEqual(obj1.plaintext, b"hello")
        self.assertEqual(obj1.aad, b"world")
