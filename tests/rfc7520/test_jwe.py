import json
from tests.base import TestFixture, load_key
from joserfc.jwk import ECKey, OctKey
from joserfc.jwe import (
    GeneralJSONEncryption,
    FlattenedJSONEncryption,
    encrypt_compact,
    decrypt_compact,
    encrypt_json,
    decrypt_json,
)


payload = (
    b"You can trust us to stick with you through thick and "
    b"thin\xe2\x80\x93to the bitter end. And you can trust us to "
    b"keep any secret of yours\xe2\x80\x93closer than you keep it "
    b"yourself. But you cannot trust us to let you face trouble "
    b"alone, and go off without a word. We are your friends, Frodo."
)


class TestJWERFC7520(TestFixture):
    def run_test(self, data):
        protected = data["protected"]
        key = load_key(data["key"])
        algorithms = [protected["alg"], protected["enc"]]
        value1 = encrypt_compact(protected, payload, key, algorithms=algorithms)
        obj1 = decrypt_compact(value1, key, algorithms=algorithms)
        compact_obj = decrypt_compact(data["compact"], key, algorithms=algorithms)
        self.assertEqual(obj1.protected, compact_obj.protected)
        self.assertEqual(obj1.plaintext, compact_obj.plaintext)

        enc1 = GeneralJSONEncryption(protected, payload)
        enc1.add_recipient(None, key)
        value2 = encrypt_json(enc1, None, algorithms=algorithms)
        obj2 = decrypt_json(value2, key, algorithms=algorithms)
        self.assertEqual(obj2.protected, protected)
        self.assertFalse(obj2.flattened)
        self.assertEqual(obj2.plaintext, payload)

        if "general_json" in data:
            general_obj = decrypt_json(data["general_json"], key, algorithms=algorithms)
            self.assertEqual(general_obj.protected, protected)
            self.assertEqual(general_obj.plaintext, payload)
            self.assertFalse(general_obj.flattened)

        enc2 = FlattenedJSONEncryption(protected, payload)
        enc2.add_recipient(None, key)
        value3 = encrypt_json(enc2, None, algorithms=algorithms)
        obj3 = decrypt_json(value3, key, algorithms=algorithms)
        self.assertEqual(obj3.protected, protected)
        self.assertEqual(obj3.plaintext, payload)
        self.assertTrue(obj3.flattened)
        if "flattened_json" in data:
            flattened_obj = decrypt_json(data["flattened_json"], key, algorithms=algorithms)
            self.assertEqual(flattened_obj.protected, protected)
            self.assertEqual(flattened_obj.plaintext, payload)
            self.assertTrue(flattened_obj.flattened)

    def run_test_agreement(self, data):
        protected = data["protected"]
        ephemeral_key = ECKey.import_key(data["epk"])
        expected_header = {**protected, "epk": ephemeral_key.as_dict(private=False)}
        key = load_key(data["key"])
        algorithms = [protected["alg"], protected["enc"]]
        compact_obj = decrypt_compact(data["compact"], key, algorithms=algorithms)
        self.assertEqual(compact_obj.plaintext, payload)
        self.assertEqual(compact_obj.protected, expected_header)

        general_obj = decrypt_json(data["general_json"], key, algorithms=algorithms)
        self.assertEqual(general_obj.plaintext, payload)
        self.assertEqual(general_obj.protected, expected_header)

        if "flattened_json" in data:
            flattened_obj = decrypt_json(data["flattened_json"], key, algorithms=algorithms)
            self.assertEqual(flattened_obj.plaintext, payload)
            self.assertEqual(flattened_obj.protected, expected_header)

        enc3 = GeneralJSONEncryption(protected, payload)
        enc3.add_recipient(None, key)
        enc3.recipients[0].ephemeral_key = ephemeral_key

        value2 = encrypt_json(enc3, None, algorithms=algorithms)
        obj2 = decrypt_json(value2, key, algorithms=algorithms)
        recipient = obj2.recipients[0]
        self.assertEqual(recipient.headers(), expected_header)

        enc4 = FlattenedJSONEncryption(protected, payload)
        enc4.add_recipient(None, key)
        enc4.recipients[0].ephemeral_key = ephemeral_key
        value3 = encrypt_json(enc4, None, algorithms=algorithms)
        obj3 = decrypt_json(value3, key, algorithms=algorithms)
        recipient = obj3.recipients[0]
        self.assertEqual(recipient.headers(), expected_header)

    def test_5_3(self):
        # Key Wrap Using PBES2-AES-KeyWrap with AES-CBC-HMAC-SHA2
        plaintext = {
            "keys": [
                {
                    "kty": "oct",
                    "kid": "77c7e2b8-6e13-45cf-8672-617b5b45243a",
                    "use": "enc",
                    "alg": "A128GCM",
                    "k": "XctOhJAkA-pD9Lh7ZgW_2A",
                },
                {
                    "kty": "oct",
                    "kid": "81b20965-8332-43d9-a468-82160ad91ac8",
                    "use": "enc",
                    "alg": "A128KW",
                    "k": "GZy6sIZ6wl9NJOKB-jnmVQ",
                },
                {
                    "kty": "oct",
                    "kid": "18ec08e1-bfa9-4d95-b205-2b4dd1d4321d",
                    "use": "enc",
                    "alg": "A256GCMKW",
                    "k": "qC57l_uxcm7Nm3K-ct4GFjx8tM1U8CZ0NLBvdQstiS8",
                },
            ]
        }
        password = OctKey.import_key(b"entrap_o\xe2\x80\x93peter_long\xe2\x80\x93credit_tun")
        protected = {
            "alg": "PBES2-HS512+A256KW",
            "p2s": "8Q1SzinasR3xchYz6ZZcHA",
            "p2c": 8192,
            "cty": "jwk-set+json",
            "enc": "A128CBC-HS256",
        }
        compact_data = """
        eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ciLCJwMnMiOiI4UTFTemluYXNSM3
        hjaFl6NlpaY0hBIiwicDJjIjo4MTkyLCJjdHkiOiJqd2stc2V0K2pzb24iLCJl
        bmMiOiJBMTI4Q0JDLUhTMjU2In0
        .
        d3qNhUWfqheyPp4H8sjOWsDYajoej4c5Je6rlUtFPWdgtURtmeDV1g
        .
        VBiCzVHNoLiR3F4V82uoTQ
        .
        23i-Tb1AV4n0WKVSSgcQrdg6GRqsUKxjruHXYsTHAJLZ2nsnGIX86vMXqIi6IR
        sfywCRFzLxEcZBRnTvG3nhzPk0GDD7FMyXhUHpDjEYCNA_XOmzg8yZR9oyjo6l
        TF6si4q9FZ2EhzgFQCLO_6h5EVg3vR75_hkBsnuoqoM3dwejXBtIodN84PeqMb
        6asmas_dpSsz7H10fC5ni9xIz424givB1YLldF6exVmL93R3fOoOJbmk2GBQZL
        _SEGllv2cQsBgeprARsaQ7Bq99tT80coH8ItBjgV08AtzXFFsx9qKvC982KLKd
        PQMTlVJKkqtV4Ru5LEVpBZXBnZrtViSOgyg6AiuwaS-rCrcD_ePOGSuxvgtrok
        AKYPqmXUeRdjFJwafkYEkiuDCV9vWGAi1DH2xTafhJwcmywIyzi4BqRpmdn_N-
        zl5tuJYyuvKhjKv6ihbsV_k1hJGPGAxJ6wUpmwC4PTQ2izEm0TuSE8oMKdTw8V
        3kobXZ77ulMwDs4p
        .
        0HlwodAhOCILG5SQ2LQ9dg
        """.replace(" ", "").replace("\n", "")
        algorithms = [protected["alg"], protected["enc"]]

        value1 = encrypt_compact(protected, json.dumps(plaintext), password, algorithms=algorithms)
        obj1 = decrypt_compact(value1, password, algorithms=algorithms)
        self.assertEqual(json.loads(obj1.plaintext), plaintext)
        compact_obj = decrypt_compact(compact_data, password, algorithms=algorithms)
        self.assertEqual(json.loads(compact_obj.plaintext), plaintext)


TestJWERFC7520.load_fixture("jwe_rfc7520.json")
