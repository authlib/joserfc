import json
from joserfc.jwe import encrypt_compact, decrypt_compact, JWERegistry
from joserfc.jwk import RSAKey, ECKey
from joserfc.rfc7518.jwe_encs import JWE_ENC_MODELS
from joserfc.util import json_b64encode
from unittest import TestCase
from tests.util import read_key


class TestJWECompact(TestCase):
    def run_case(self, alg, enc, private_key, public_key):
        protected = {"alg": alg, "enc": enc}
        payload = b'hello'
        algorithms = {"alg": [alg], "enc": [enc]}
        registry = JWERegistry(algorithms=algorithms)
        result = encrypt_compact(
            protected, payload, public_key,
            registry=registry,
        )
        self.assertEqual(result.count(b'.'), 4)

        obj = decrypt_compact(
            result, private_key,
            registry=registry,
        )
        self.assertEqual(obj.payload, payload)

    def run_cases(self, algs, private_key, public_key):
        for alg in algs:
            for enc in JWE_ENC_MODELS:
                self.run_case(alg, enc.name, private_key, public_key)

    def test_with_rsa_key(self):
        private_key = RSAKey.import_key(read_key('openssl-rsa-private.pem'))
        public_key = RSAKey.import_key(read_key('openssl-rsa-public.pem'))
        algs = ['RSA1_5', 'RSA-OAEP', 'RSA-OAEP-256']
        self.run_cases(algs, private_key, public_key)

    def test_with_ec_key(self):
        algs = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW']
        for size in [256, 384, 512]:
            private_key = ECKey.import_key(read_key(f'ec-p{size}-private.pem'))
            public_key = ECKey.import_key(read_key(f'ec-p{size}-public.pem'))
            self.run_cases(algs, private_key, public_key)


class TestCompactExamples(TestCase):
    def test_RSAES_OAEP_and_AES_GCM(self):
        # https://www.rfc-editor.org/rfc/rfc7516#appendix-A.1
        # Example JWE using RSAES-OAEP and AES GCM
        payload = b'The true sign of intelligence is not knowledge but imagination.'

        # A.1.1.  JOSE Header
        protected = {"alg": "RSA-OAEP", "enc": "A256GCM"}
        self.assertEqual(json_b64encode(protected), b"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ")

        # A.1.2.  Content Encryption Key (CEK)
        CEK = bytes([
            177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
            212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
            234, 64, 252
        ])

        # A.1.3.  Key Encryption
        key = RSAKey.import_key(json.loads(read_key('RFC7516-A.1.3.json')))

        # resulting encrypted key
        encrypted_key = bytes([
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

        # A.1.5.  Additional Authenticated Data
        aad = bytes([
            101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
            116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73,
            54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81
        ])
        self.assertEqual(json_b64encode(protected), aad)

        # A.1.6.  Content Encryption
        ciphertext = bytes([
            229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122,
            233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111,
            104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32,
            123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205,
            160, 109, 64, 63, 192
        ])
        tag = bytes([
            92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
            210, 145
        ])

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
