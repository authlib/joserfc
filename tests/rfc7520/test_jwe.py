from tests.base import TestFixture, load_key
from joserfc.jwe import (
    JSONEncryption,
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

        enc_data = JSONEncryption(protected, payload)
        enc_data.add_recipient(None, key)
        enc_data.flatten = False
        value2 = encrypt_json(enc_data, None, algorithms=algorithms)
        obj2 = decrypt_json(value2, key, algorithms=algorithms)
        general_obj = decrypt_json(data["general_json"], key, algorithms=algorithms)
        self.assertEqual(obj2.protected, general_obj.protected)
        self.assertEqual(obj2.flatten, general_obj.flatten)
        self.assertEqual(general_obj.flatten, False)

        enc_data.flatten = True
        value3 = encrypt_json(enc_data, None, algorithms=algorithms)
        obj3 = decrypt_json(value3, key, algorithms=algorithms)
        flattened_obj = decrypt_json(data["flattened_json"], key, algorithms=algorithms)
        self.assertEqual(obj3.protected, flattened_obj.protected)
        self.assertEqual(obj3.flatten, flattened_obj.flatten)
        self.assertEqual(flattened_obj.flatten, True)


TestJWERFC7520.load_fixture("jwe_rfc7520.json")
