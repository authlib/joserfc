from .models import EncryptionData, JWEEncModel
from .registry import JWERegistry
from ..errors import DecodeError
from ..util import (
    json_b64encode,
    urlsafe_b64encode,
)


def perform_encrypt(obj: EncryptionData, registry: JWERegistry, sender_key=None) -> EncryptionData:
    enc = registry.get_enc(obj.protected["enc"])
    items = _prepare_recipients(obj, enc, registry)
    for recipient, alg in items:
        # from step 3 to step 7
        if sender_key:
            ek = alg.encrypt_recipient(enc, recipient, sender_key)
        else:
            ek = alg.encrypt_recipient(enc, recipient, recipient.recipient_key)
        recipient.encrypted_key = ek

    # Step 9, Generate a random JWE Initialization Vector of the correct size
    # for the content encryption algorithm (if required for the algorithm);
    # otherwise, let the JWE Initialization Vector be the empty octet sequence.
    iv = enc.generate_iv()
    obj.decoded["iv"] = iv

    # Step 10, Compute the encoded Initialization Vector value
    # BASE64URL(JWE Initialization Vector).
    obj.encoded["iv"] = urlsafe_b64encode(iv)

    # Step 11, If a "zip" parameter was included, compress the plaintext using
    # the specified compression algorithm and let M be the octet sequence
    # representing the compressed plaintext; otherwise, let M be the octet
    # sequence representing the plaintext.
    if "zip" in obj.protected:
        zip_ = registry.get_zip(obj.protected["zip"])
        obj.segments["plaintext"] = zip_.compress(obj.payload)

    # Step 13, Compute the Encoded Protected Header value BASE64URL(UTF8(JWE Protected Header)).
    aad = json_b64encode(obj.protected, "ascii")

    # Step 14, Let the Additional Authenticated Data encryption parameter be
    # ASCII(Encoded Protected Header).  However, if a JWE AAD value is
    # present (which can only be the case when using the JWE JSON Serialization),
    # instead let the Additional Authenticated Data encryption parameter be
    # ASCII(Encoded Protected Header || '.' || BASE64URL(JWE AAD)).
    if not obj.compact and obj.aad:
        aad = aad + b"." + urlsafe_b64encode(obj.aad)
    obj.encoded["aad"] = aad

    # perform encryption
    ciphertext = enc.encrypt(obj)
    obj.decoded["ciphertext"] = ciphertext
    obj.encoded["ciphertext"] = urlsafe_b64encode(ciphertext)
    obj.encoded["tag"] = urlsafe_b64encode(obj.decoded["tag"])
    return obj


def perform_decrypt(obj: EncryptionData, registry: JWERegistry, sender_key=None) -> EncryptionData:
    enc = registry.get_enc(obj.protected["enc"])

    aad = json_b64encode(obj.protected, "ascii")
    if not obj.compact and obj.aad:
        aad = aad + b"." + urlsafe_b64encode(obj.aad)
    obj.encoded["aad"] = aad

    cek_set = set()
    for recipient in obj.recipients:
        headers = recipient.headers()
        registry.check_header(headers, True)

        # Step 6, Determine the Key Management Mode employed by the algorithm
        # specified by the "alg" (algorithm) Header Parameter.
        alg = registry.get_alg(headers["alg"])
        if sender_key:
            cek = alg.decrypt_recipient(enc, recipient, sender_key)
        else:
            cek = alg.decrypt_recipient(enc, recipient, recipient.recipient_key)
        cek_set.add(cek)

    if len(cek_set) > 1:
        raise DecodeError('Multiple "cek" found')

    cek = cek_set.pop()
    if len(cek) * 8 != enc.cek_size:
        raise ValueError('Invalid "cek" length')

    obj.cek = cek
    msg = enc.decrypt(obj)
    if "zip" in obj.protected:
        zip_ = registry.get_zip(obj.protected["zip"])
        obj.payload = zip_.decompress(msg)
    else:
        obj.payload = msg
    return obj


def _prepare_recipients(obj: EncryptionData, enc: JWEEncModel, registry: JWERegistry):
    modes = set()
    items = []
    for recipient in obj.recipients:
        headers = recipient.headers()
        registry.check_header(headers)

        # Step 1, determine the algorithms
        # https://www.rfc-editor.org/rfc/rfc7516#section-5.1
        alg = registry.get_alg(headers["alg"])
        modes.add(alg.direct_mode)
        items.append((recipient, alg))

    if len(modes) > 1:
        # TODO
        raise

    alg = items[0][1]

    # Step 2, When Key Wrapping, Key Encryption,
    # or Key Agreement with Key Wrapping are employed,
    # generate a random CEK value.
    if not alg.direct_mode and not obj.cek:
        obj.cek = enc.generate_cek()

    return items
