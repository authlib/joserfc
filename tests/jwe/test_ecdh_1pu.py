from unittest import TestCase
from joserfc.jwe import (
    JWERegistry,
    encrypt_compact,
    decrypt_compact,
    encrypt_json,
    decrypt_json,
)
from joserfc.jwk import KeySet
from joserfc.rfc7518.jwe_encs import JWE_ENC_MODELS
from joserfc.drafts.jwe_ecdh_1pu import JWE_ALG_MODELS
from tests.fixtures import TestFixture
from tests.keys import load_key


for model in JWE_ALG_MODELS:
    JWERegistry.register(model)

ecdh_registry = JWERegistry(
    algorithms=[m.name for m in JWE_ALG_MODELS] + [enc.name for enc in JWE_ENC_MODELS]
)


class TestECDH1PUCompact(TestFixture):
    def run_test(self, case, recipient_key, sender_key):
        value: str = case["value"]
        payload = case["payload"].encode("utf-8")
        obj = decrypt_compact(
            value.encode("utf-8"),
            private_key=recipient_key,
            registry=ecdh_registry,
            sender_key=sender_key,
        )
        self.assertEqual(obj.protected["alg"], case["alg"])
        self.assertEqual(obj.protected["enc"], case["enc"])
        self.assertEqual(obj.plaintext, payload)

    def run_compact_case(self, alg: str, enc: str, recipient_key, sender_key):
        protected = {"alg": alg, "enc": enc}
        value = encrypt_compact(
            protected, b'hello',
            public_key=recipient_key,
            registry=ecdh_registry,
            sender_key=sender_key,
        )
        self.assertEqual(value.count(b"."), 4)
        obj = decrypt_compact(
            value,
            private_key=recipient_key,
            registry=ecdh_registry,
            sender_key=sender_key,
        )
        self.assertEqual(obj.plaintext, b'hello')

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
            'ECDH-1PU+A128KW',
            'ECDH-1PU+A192KW',
            'ECDH-1PU+A256KW',
        ]
        allowed_enc_values = [
            'A128CBC-HS256',
            'A192CBC-HS384',
            'A256CBC-HS512',
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


def add_compact_fixtures():
    alice_key = load_key("ec-p256-alice.json")
    bob_key = load_key("ec-p256-bob.json")
    TestECDH1PUCompact.load_fixture('jwe_compact_ecdh_1pu.json', bob_key, alice_key)

add_compact_fixtures()


class TestECDH1PUJSON(TestCase):
    def test_example_B(self):
        # https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04#appendix-B.11
        result = {
            "protected": (
                "eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1Ijoi"
                "UVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0eSI6Ik9L"
                "UCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhHczluSGt3ZzFB"
                "RnFVQUZhMzlkeUJjIn19"
            ),
            "unprotected": {"jku":"https://alice.example.com/keys.jwks"},
            "recipients":[
                {
                    "header": {"kid":"bob-key-2"},
                    "encrypted_key": (
                        "pOMVA9_PtoRe7xXW1139NzzN1UhiFoio8lGto9cf0t8PyU-sjNXH8-LIRLycq8CH"
                        "JQbDwvQeU1cSl55cQ0hGezJu2N9IY0QN"
                    )
                },
                {
                    "header": {"kid":"2021-05-06"},
                    "encrypted_key": (
                        "56GVudgRLIMEElQ7DpXsijJVRSWUSDNdbWkdV3g0GUNq6hcT_GkxwnxlPIWrTXCq"
                        "RpVKQC8fe4z3PQ2YH2afvjQ28aiCTWFE"
                    )
                 }
            ],
            "iv": "AAECAwQFBgcICQoLDA0ODw",
            "ciphertext": "Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw",
            "tag": "HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ"
        }
        alice_key = load_key("okp-x25519-alice.json")
        bob_key = load_key("okp-x25519-bob.json", {"kid":"bob-key-2"})
        charlie_key = load_key("okp-x25519-charlie.json", {"kid":"2021-05-06"})
        protected = {
            "alg":"ECDH-1PU+A128KW",
            "enc":"A256CBC-HS512",
            "apu":"QWxpY2U",
            "apv":"Qm9iIGFuZCBDaGFybGll",
            "epk": {
                "kty":"OKP",
                "crv":"X25519",
                "x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"
            }
        }
        obj = decrypt_json(
            result,
            KeySet([bob_key, charlie_key]),
            registry=ecdh_registry,
            sender_key=alice_key,
        )
