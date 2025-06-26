from unittest import TestCase
from joserfc.jwe import decrypt_compact, decrypt_json
from joserfc.jwk import RSAKey, OctKey, KeySet
from joserfc.util import json_b64encode, urlsafe_b64encode, to_bytes
from joserfc.jwe import JWERegistry, default_registry as registry
from joserfc.jwe import CompactEncryption, GeneralJSONEncryption
from joserfc._rfc7516.message import perform_encrypt
from joserfc._rfc7516.compact import represent_compact
from joserfc._rfc7516.json import represent_general_json
from joserfc.errors import UnsupportedAlgorithmError
from tests.base import load_key


class TestCompactExamples(TestCase):
    def test_A1(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
        # Example JWE using RSAES-OAEP and AES GCM
        plaintext = b"The true sign of intelligence is not knowledge but imagination."

        # A.1.1.  JOSE Header
        protected = {"alg": "RSA-OAEP", "enc": "A256GCM"}
        self.assertEqual(json_b64encode(protected), b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ")

        obj = CompactEncryption(protected, plaintext)

        # A.1.2.  Content Encryption Key (CEK)
        cek = bytes(
            [
                177,
                161,
                244,
                128,
                84,
                143,
                225,
                115,
                63,
                180,
                3,
                255,
                107,
                154,
                212,
                246,
                138,
                7,
                110,
                91,
                112,
                46,
                34,
                105,
                47,
                130,
                203,
                46,
                122,
                234,
                64,
                252,
            ]
        )

        # A.1.3.  Key Encryption
        key: RSAKey = load_key("RFC7516-A.1.3.json")
        obj.attach_recipient(key)

        enc = registry.get_enc(protected["enc"])

        # resulting encrypted key
        obj.recipient.encrypted_key = bytes(
            [
                56,
                163,
                154,
                192,
                58,
                53,
                222,
                4,
                105,
                218,
                136,
                218,
                29,
                94,
                203,
                22,
                150,
                92,
                129,
                94,
                211,
                232,
                53,
                89,
                41,
                60,
                138,
                56,
                196,
                216,
                82,
                98,
                168,
                76,
                37,
                73,
                70,
                7,
                36,
                8,
                191,
                100,
                136,
                196,
                244,
                220,
                145,
                158,
                138,
                155,
                4,
                117,
                141,
                230,
                199,
                247,
                173,
                45,
                182,
                214,
                74,
                177,
                107,
                211,
                153,
                11,
                205,
                196,
                171,
                226,
                162,
                128,
                171,
                182,
                13,
                237,
                239,
                99,
                193,
                4,
                91,
                219,
                121,
                223,
                107,
                167,
                61,
                119,
                228,
                173,
                156,
                137,
                134,
                200,
                80,
                219,
                74,
                253,
                56,
                185,
                91,
                177,
                34,
                158,
                89,
                154,
                205,
                96,
                55,
                18,
                138,
                43,
                96,
                218,
                215,
                128,
                124,
                75,
                138,
                243,
                85,
                25,
                109,
                117,
                140,
                26,
                155,
                249,
                67,
                167,
                149,
                231,
                100,
                6,
                41,
                65,
                214,
                251,
                232,
                87,
                72,
                40,
                182,
                149,
                154,
                168,
                31,
                193,
                126,
                215,
                89,
                28,
                111,
                219,
                125,
                182,
                139,
                235,
                195,
                197,
                23,
                234,
                55,
                58,
                63,
                180,
                68,
                202,
                206,
                149,
                75,
                205,
                248,
                176,
                67,
                39,
                178,
                60,
                98,
                193,
                32,
                238,
                122,
                96,
                158,
                222,
                57,
                183,
                111,
                210,
                55,
                188,
                215,
                206,
                180,
                166,
                150,
                166,
                106,
                250,
                55,
                229,
                72,
                40,
                69,
                214,
                216,
                104,
                23,
                40,
                135,
                212,
                28,
                127,
                41,
                80,
                175,
                174,
                168,
                115,
                171,
                197,
                89,
                116,
                92,
                103,
                246,
                83,
                216,
                182,
                176,
                84,
                37,
                147,
                35,
                45,
                219,
                172,
                99,
                226,
                233,
                73,
                37,
                124,
                42,
                72,
                49,
                242,
                35,
                127,
                184,
                134,
                117,
                114,
                135,
                206,
            ]
        )

        # A.1.4.  Initialization Vector
        iv = bytes([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219])
        obj.base64_segments["iv"] = urlsafe_b64encode(iv)

        # A.1.5.  Additional Authenticated Data
        aad = bytes(
            [
                101,
                121,
                74,
                104,
                98,
                71,
                99,
                105,
                79,
                105,
                74,
                83,
                85,
                48,
                69,
                116,
                84,
                48,
                70,
                70,
                85,
                67,
                73,
                115,
                73,
                109,
                86,
                117,
                89,
                121,
                73,
                54,
                73,
                107,
                69,
                121,
                78,
                84,
                90,
                72,
                81,
                48,
                48,
                105,
                102,
                81,
            ]
        )
        self.assertEqual(json_b64encode(protected), aad)
        obj.base64_segments["aad"] = aad

        # A.1.6.  Content Encryption
        ciphertext = bytes(
            [
                229,
                236,
                166,
                241,
                53,
                191,
                115,
                196,
                174,
                43,
                73,
                109,
                39,
                122,
                233,
                96,
                140,
                206,
                120,
                52,
                51,
                237,
                48,
                11,
                190,
                219,
                186,
                80,
                111,
                104,
                50,
                142,
                47,
                167,
                59,
                61,
                181,
                127,
                196,
                21,
                40,
                82,
                242,
                32,
                123,
                143,
                168,
                226,
                73,
                216,
                176,
                144,
                138,
                247,
                106,
                60,
                16,
                205,
                160,
                109,
                64,
                63,
                192,
            ]
        )
        r_ciphertext, r_tag = enc.encrypt(plaintext, cek, iv, aad)
        self.assertEqual(r_ciphertext, ciphertext)
        obj.base64_segments["ciphertext"] = urlsafe_b64encode(ciphertext)

        tag = bytes([92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145])
        self.assertEqual(r_tag, tag)
        obj.base64_segments["tag"] = urlsafe_b64encode(r_tag)

        # A.1.7.  Complete Representation
        expected = (
            "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ."
            "OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
            "ipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDb"
            "Sv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaV"
            "mqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je8"
            "1860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi"
            "6UklfCpIMfIjf7iGdXKHzg."
            "48V1_ALb6US04U3b."
            "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
            "SdiwkIr3ajwQzaBtQD_A."
            "XFBoMYUZodetZdvTiFvSkQ"
        )
        self.assertEqual(represent_compact(obj), to_bytes(expected))

        jwe_data = decrypt_compact(expected, key)
        self.assertEqual(jwe_data.plaintext, plaintext)

    def test_A2(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.2
        plaintext = b"Live long and prosper."
        self.assertEqual(
            plaintext,
            bytes(
                [76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46]
            ),
        )

        # A.2.1.  JOSE Header
        protected = {"alg": "RSA1_5", "enc": "A128CBC-HS256"}
        self.assertEqual(json_b64encode(protected), b"eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")
        obj = CompactEncryption(protected, plaintext)

        # A.2.2.  Content Encryption Key (CEK)
        cek = bytes(
            [
                4,
                211,
                31,
                197,
                84,
                157,
                252,
                254,
                11,
                100,
                157,
                250,
                63,
                170,
                106,
                206,
                107,
                124,
                212,
                45,
                111,
                107,
                9,
                219,
                200,
                177,
                0,
                240,
                143,
                156,
                44,
                207,
            ]
        )

        # A.2.3.  Key Encryption
        key: RSAKey = load_key("RFC7516-A.2.3.json")
        obj.attach_recipient(key)

        obj.recipient.encrypted_key = bytes(
            [
                80,
                104,
                72,
                58,
                11,
                130,
                236,
                139,
                132,
                189,
                255,
                205,
                61,
                86,
                151,
                176,
                99,
                40,
                44,
                233,
                176,
                189,
                205,
                70,
                202,
                169,
                72,
                40,
                226,
                181,
                156,
                223,
                120,
                156,
                115,
                232,
                150,
                209,
                145,
                133,
                104,
                112,
                237,
                156,
                116,
                250,
                65,
                102,
                212,
                210,
                103,
                240,
                177,
                61,
                93,
                40,
                71,
                231,
                223,
                226,
                240,
                157,
                15,
                31,
                150,
                89,
                200,
                215,
                198,
                203,
                108,
                70,
                117,
                66,
                212,
                238,
                193,
                205,
                23,
                161,
                169,
                218,
                243,
                203,
                128,
                214,
                127,
                253,
                215,
                139,
                43,
                17,
                135,
                103,
                179,
                220,
                28,
                2,
                212,
                206,
                131,
                158,
                128,
                66,
                62,
                240,
                78,
                186,
                141,
                125,
                132,
                227,
                60,
                137,
                43,
                31,
                152,
                199,
                54,
                72,
                34,
                212,
                115,
                11,
                152,
                101,
                70,
                42,
                219,
                233,
                142,
                66,
                151,
                250,
                126,
                146,
                141,
                216,
                190,
                73,
                50,
                177,
                146,
                5,
                52,
                247,
                28,
                197,
                21,
                59,
                170,
                247,
                181,
                89,
                131,
                241,
                169,
                182,
                246,
                99,
                15,
                36,
                102,
                166,
                182,
                172,
                197,
                136,
                230,
                120,
                60,
                58,
                219,
                243,
                149,
                94,
                222,
                150,
                154,
                194,
                110,
                227,
                225,
                112,
                39,
                89,
                233,
                112,
                207,
                211,
                241,
                124,
                174,
                69,
                221,
                179,
                107,
                196,
                225,
                127,
                167,
                112,
                226,
                12,
                242,
                16,
                24,
                28,
                120,
                182,
                244,
                213,
                244,
                153,
                194,
                162,
                69,
                160,
                244,
                248,
                63,
                165,
                141,
                4,
                207,
                249,
                193,
                79,
                131,
                0,
                169,
                233,
                127,
                167,
                101,
                151,
                125,
                56,
                112,
                111,
                248,
                29,
                232,
                90,
                29,
                147,
                110,
                169,
                146,
                114,
                165,
                204,
                71,
                136,
                41,
                252,
            ]
        )

        # A.2.4.  Initialization Vector
        iv = bytes([3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101])
        obj.base64_segments["iv"] = urlsafe_b64encode(iv)
        self.assertEqual(obj.base64_segments["iv"], b"AxY8DCtDaGlsbGljb3RoZQ")

        # A.2.5.  Additional Authenticated Data
        aad = bytes(
            [
                101,
                121,
                74,
                104,
                98,
                71,
                99,
                105,
                79,
                105,
                74,
                83,
                85,
                48,
                69,
                120,
                88,
                122,
                85,
                105,
                76,
                67,
                74,
                108,
                98,
                109,
                77,
                105,
                79,
                105,
                74,
                66,
                77,
                84,
                73,
                52,
                81,
                48,
                74,
                68,
                76,
                85,
                104,
                84,
                77,
                106,
                85,
                50,
                73,
                110,
                48,
            ]
        )
        self.assertEqual(json_b64encode(protected), aad)
        obj.base64_segments["aad"] = aad

        # A.2.6.  Content Encryption
        ciphertext = bytes(
            [
                40,
                57,
                83,
                181,
                119,
                33,
                133,
                148,
                198,
                185,
                243,
                24,
                152,
                230,
                6,
                75,
                129,
                223,
                127,
                19,
                210,
                82,
                183,
                230,
                168,
                33,
                215,
                104,
                143,
                112,
                56,
                102,
            ]
        )
        enc = registry.get_enc(protected["enc"])
        r_ciphertext, r_tag = enc.encrypt(plaintext, cek, iv, aad)
        self.assertEqual(r_ciphertext, ciphertext)
        obj.base64_segments["ciphertext"] = urlsafe_b64encode(ciphertext)

        self.assertEqual(r_tag, bytes([246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191]))
        obj.base64_segments["tag"] = urlsafe_b64encode(r_tag)

        expected = (
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
            "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm"
            "1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7Pc"
            "HALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIF"
            "NPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8"
            "rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv"
            "-B3oWh2TbqmScqXMR4gp_A."
            "AxY8DCtDaGlsbGljb3RoZQ."
            "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
            "9hH0vgRfYgPnAHOd8stkvw"
        )
        self.assertEqual(represent_compact(obj), to_bytes(expected))

        # RSA1_5 is not allowed by default
        self.assertRaises(UnsupportedAlgorithmError, decrypt_compact, expected, key)
        _registry = JWERegistry(algorithms=["RSA1_5", "A128CBC-HS256"])
        jwe_data = decrypt_compact(expected, key, registry=_registry)
        self.assertEqual(jwe_data.plaintext, plaintext)

    def test_A3(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.3
        plaintext = b"Live long and prosper."
        protected = {"alg": "A128KW", "enc": "A128CBC-HS256"}
        key = OctKey.import_key({"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"})
        expected = (
            "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
            "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ."
            "AxY8DCtDaGlsbGljb3RoZQ."
            "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY."
            "U0m_YmjN04DJvceFICbCVQ"
        )

        extract_data = decrypt_compact(expected, key)
        self.assertEqual(extract_data.protected, protected)
        self.assertEqual(extract_data.plaintext, plaintext)

    def test_A4(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.4
        # A.4.1.  JWE Per-Recipient Unprotected Headers
        recipient1 = {"alg": "RSA1_5", "kid": "2011-04-29"}
        recipient2 = {"alg": "A128KW", "kid": "7"}

        # The algorithm and key used for the first recipient are the same as
        # that used in Appendix A.2.
        key1: RSAKey = load_key("RFC7516-A.2.3.json", {"kid": "2011-04-29"})

        # The algorithm and key used for the second recipient are the same as
        # that used in Appendix A.3.
        key2 = OctKey.import_key({"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}, {"kid": "7"})
        keys = KeySet([key1, key2])

        # A.4.2.  JWE Protected Header
        protected = {"enc": "A128CBC-HS256"}
        self.assertEqual(json_b64encode(protected), b"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0")

        # A.4.3.  JWE Shared Unprotected Header
        shared_header = {"jku": "https://server.example.com/keys.jwks"}

        # A.4.6.  Content Encryption
        plaintext = b"Live long and prosper."

        ciphertext = bytes(
            [
                40,
                57,
                83,
                181,
                119,
                33,
                133,
                148,
                198,
                185,
                243,
                24,
                152,
                230,
                6,
                75,
                129,
                223,
                127,
                19,
                210,
                82,
                183,
                230,
                168,
                33,
                215,
                104,
                143,
                112,
                56,
                102,
            ]
        )

        # A.4.7.  Complete JWE JSON Serialization Representation
        expected = {
            "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            "unprotected": {"jku": "https://server.example.com/keys.jwks"},
            "recipients": [
                {
                    "header": {"alg": "RSA1_5", "kid": "2011-04-29"},
                    "encrypted_key": (
                        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"
                        "kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"
                        "GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"
                        "YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"
                        "cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"
                        "wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A"
                    ),
                },
                {
                    "header": {"alg": "A128KW", "kid": "7"},
                    "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
                },
            ],
            "iv": "AxY8DCtDaGlsbGljb3RoZQ",
            "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "tag": "Mz-VPPyU4RlcuYv1IwIvzw",
        }

        _registry = JWERegistry(algorithms=["RSA1_5", "A128KW", "A128CBC-HS256"])
        jwe_data = decrypt_json(expected, keys, registry=_registry)
        self.assertEqual(jwe_data.plaintext, plaintext)
        self.assertEqual(jwe_data.protected, protected)
        self.assertEqual(jwe_data.unprotected, shared_header)
        self.assertEqual(jwe_data.bytes_segments["ciphertext"], ciphertext)
        self.assertEqual(jwe_data.recipients[0].header, recipient1)
        self.assertEqual(jwe_data.recipients[1].header, recipient2)

    def test_A4_perform(self):
        recipient1 = {"alg": "RSA1_5", "kid": "2011-04-29"}
        recipient2 = {"alg": "A128KW", "kid": "7"}
        protected = {"enc": "A128CBC-HS256"}
        shared_header = {"jku": "https://server.example.com/keys.jwks"}
        key1: RSAKey = load_key("RFC7516-A.2.3.json", {"kid": "2011-04-29"})
        key2 = OctKey.import_key({"kty": "oct", "k": "GawgguFyGrWKav7AX4VKUg"}, {"kid": "7"})
        payload = b"Live long and prosper."
        obj = GeneralJSONEncryption(protected, payload, shared_header)
        obj.add_recipient(recipient1, key1)
        obj.add_recipient(recipient2, key2)
        _registry = JWERegistry(algorithms=["RSA1_5", "A128KW", "A128CBC-HS256"])
        perform_encrypt(obj, _registry)
        expected = represent_general_json(obj)

        keys = KeySet([key1, key2])
        jwe_data = decrypt_json(expected, keys, registry=_registry)
        self.assertEqual(jwe_data.plaintext, payload)
