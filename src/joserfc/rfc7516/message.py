from .types import EncryptionData
from .registry import JWERegistry
from ..util import (
    to_bytes,
    json_b64encode,
    urlsafe_b64encode,
)


def perform_encrypt(obj: EncryptionData, registry: JWERegistry) -> EncryptionData:
    enc = registry.get_enc(obj.protected['enc'])

    # Step 8 for each recipient
    for recipient in obj.recipients:
        headers = recipient.headers()
        registry.check_header(headers)

        # Step 1, determine the algorithms
        # https://www.rfc-editor.org/rfc/rfc7516#section-5.1
        alg = registry.get_alg(headers['alg'])

        # Step 2, When Key Wrapping, Key Encryption,
        # or Key Agreement with Key Wrapping are employed,
        # generate a random CEK value.
        if not alg.direct_mode:
            obj.cek = enc.generate_cek()

        # from step 3 to step 7
        ek = alg.encrypt_recipient(enc, recipient, recipient.recipient_key)
        recipient.encrypted_key = ek

    # Step 9, Generate a random JWE Initialization Vector of the correct size
    # for the content encryption algorithm (if required for the algorithm);
    # otherwise, let the JWE Initialization Vector be the empty octet sequence.
    iv = enc.generate_iv()
    obj.decoded['iv'] = iv

    # Step 10, Compute the encoded Initialization Vector value
    # BASE64URL(JWE Initialization Vector).
    obj.encoded['iv'] = urlsafe_b64encode(iv)

    # Step 11, If a "zip" parameter was included, compress the plaintext using
    # the specified compression algorithm and let M be the octet sequence
    # representing the compressed plaintext; otherwise, let M be the octet
    # sequence representing the plaintext.
    if 'zip' in obj.protected:
        zip_ = registry.get_zip(obj.protected['zip'])
        obj.plaintext = zip_.compress(obj.payload)
    else:
        obj.plaintext = obj.payload

    # Step 12

    # Step 13, Compute the Encoded Protected Header value BASE64URL(UTF8(JWE Protected Header)).
    aad = json_b64encode(obj.protected, 'ascii')

    # Step 14, Let the Additional Authenticated Data encryption parameter be
    # ASCII(Encoded Protected Header).  However, if a JWE AAD value is
    # present (which can only be the case when using the JWE JSON Serialization),
    # instead let the Additional Authenticated Data encryption parameter be
    # ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).
    if not obj.compact and 'aad' in obj.protected:
        aad = aad + b'.' + urlsafe_b64encode(to_bytes(obj.protected['aad']))
    obj.encoded['aad'] = aad

    # perform encryption
    ciphertext = enc.encrypt(obj)
    obj.decoded['ciphertext'] = ciphertext
    return obj


def perform_decrypt(obj: EncryptionData, registry: JWERegistry) -> EncryptionData:
    enc = registry.get_enc(obj.protected['enc'])

    cek_set = set()

    for recipient in obj.recipients:
        headers = recipient.headers()
        registry.check_header(obj.protected, True)

        # Step 6, Determine the Key Management Mode employed by the algorithm
        # specified by the "alg" (algorithm) Header Parameter.
        alg = registry.get_alg(headers['alg'])
        cek = alg.decrypt_recipient(enc, recipient, recipient.recipient_key)
        cek_set.add(cek)

    if len(cek_set) > 1:
        raise

    if len(cek) * 8 != enc.cek_size:
        raise ValueError('Invalid "cek" length')

    obj.cek = cek
    msg = enc.decrypt(obj)
    if 'zip' in obj.protected:
        zip_ = registry.get_zip(obj.protected['zip'])
        obj.payload = zip_.decompress(msg)
    else:
        obj.payload = msg
    return obj
