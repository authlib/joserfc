from unittest import TestCase
from joserfc.jwk import RSAKey


class TestOctKey(TestCase):
    def test_import_key_from_dict(self):
        # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.1
        data = {
            "kty":"RSA",
            "n": (
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86"
                "zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5"
                "JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQ"
                "MicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyr"
                "dkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF4"
                "4-csFCur-kEgU8awapJzKnqDKgw"
            ),
            "e":"AQAB",
            "alg":"RS256",
            "kid":"2011-04-29",
        }
        key = RSAKey.import_key(data)
        self.assertEqual(key.as_dict(), data)
        self.assertEqual(key.is_private, False)
