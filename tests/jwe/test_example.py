import json
from joserfc.jwe import decrypt_compact
from joserfc.jwk import RSAKey, ECKey
from joserfc.util import json_b64encode, urlsafe_b64encode, to_bytes
from joserfc.rfc7516.registry import default_registry as registry
from joserfc.rfc7516.types import EncryptionData
from joserfc.rfc7516.message import perform_encrypt
from joserfc.rfc7516.compact import represent_compact
from unittest import TestCase
from tests.util import read_key


class TestCompactExamples(TestCase):
    def test_A1(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
        # Example JWE using RSAES-OAEP and AES GCM
        payload = b'The true sign of intelligence is not knowledge but imagination.'

        # A.1.1.  JOSE Header
        protected = {"alg": "RSA-OAEP", "enc": "A256GCM"}
        self.assertEqual(
            json_b64encode(protected),
            b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ"
        )

        obj = EncryptionData(protected, payload)
        obj.plaintext = payload

        # A.1.2.  Content Encryption Key (CEK)
        CEK = bytes([
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252
        ])
        obj.cek = CEK

        # A.1.3.  Key Encryption
        key = RSAKey.import_key(json.loads(read_key('RFC7516-A.1.3.json')))
        obj.add_recipient(key)

        alg = registry.get_alg(protected['alg'])
        enc = registry.get_enc(protected['enc'])

        # resulting encrypted key
        recipient = obj.recipients[0]
        recipient.encrypted_key = bytes([
            56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203,
            22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216,
            82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220,
            145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214,
            74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182,
            13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228,
            173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158,
            89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138,
            243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6,
            41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126,
            215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58,
            63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
            193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215,
            206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216,
            104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197,
            89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219,
            172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134,
            117, 114, 135, 206
        ])

        # A.1.4.  Initialization Vector
        iv = bytes([227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219])
        obj.decoded['iv'] = iv
        obj.encoded['iv'] = urlsafe_b64encode(iv)

        # A.1.5.  Additional Authenticated Data
        aad = bytes([
            101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
            116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
            54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81
        ])
        self.assertEqual(json_b64encode(protected), aad)
        obj.encoded['aad'] = aad

        # A.1.6.  Content Encryption
        ciphertext = bytes([
            229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
            233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
            104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
            123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
            160, 109, 64, 63, 192
        ])
        self.assertEqual(enc.encrypt(obj), ciphertext)
        obj.decoded['ciphertext'] = ciphertext

        tag = bytes([
            92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
            210, 145
        ])
        self.assertEqual(obj.decoded['tag'], tag)

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
        self.assertEqual(jwe_data.payload, payload)

    def test_A4(self):
        # A.4.1.  JWE Per-Recipient Unprotected Headers
        recipient_headers = [
            {"alg": "RSA1_5", "kid": "2011-04-29"},
            {"alg": "A128KW", "kid": "7"},
        ]

        # A.4.2.  JWE Protected Header
        protected = {"enc": "A128CBC-HS256"}
        self.assertEqual(
            json_b64encode(protected),
            b'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0'
        )

        # A.4.3.  JWE Shared Unprotected Header
        shared_header = {"jku": "https://server.example.com/keys.jwks"}

        # A.4.5.  Additional Authenticated Data
        aad = bytes([
            101, 121, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73,
            52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48
        ])

        # A.4.6.  Content Encryption
        payload = b"Live long and prosper."
        ciphertext = bytes([
            40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6,
            75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143,
            112, 56, 102
        ])

        # A.4.7.  Complete JWE JSON Serialization Representation
        expected = {
            "protected": "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
            "unprotected": {"jku":"https://server.example.com/keys.jwks"},
            "recipients":[
                {
                    "header": {"alg":"RSA1_5","kid":"2011-04-29"},
                    "encrypted_key": (
                        "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-"
                        "kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKx"
                        "GHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3"
                        "YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPh"
                        "cCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPg"
                        "wCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A")
                },
                {
                    "header": {"alg":"A128KW","kid":"7"},
                    "encrypted_key": "6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"
                }
            ],
            "iv": "AxY8DCtDaGlsbGljb3RoZQ",
            "ciphertext": "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "tag": "Mz-VPPyU4RlcuYv1IwIvzw"
        }
