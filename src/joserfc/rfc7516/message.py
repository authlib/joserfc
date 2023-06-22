from .models import (
    JWEDirectEncryption,
    EncryptionData,
    Recipient,
    JWEEncModel,
)
from .registry import JWERegistry
from ..errors import DecodeError, InvalidCEKLengthError
from ..util import (
    json_b64encode,
    urlsafe_b64encode,
)


def perform_encrypt(obj: EncryptionData, registry: JWERegistry, sender_key=None) -> EncryptionData:
    enc = registry.get_enc(obj.protected["enc"])

    cek = b""
    for recipient in obj.recipients:
        cek = encrypt_recipient(enc, recipient, registry, cek)

    obj.cek = cek
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
        cek = decrypt_recipient(enc, recipient, registry)
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


def encrypt_recipient(enc: JWEEncModel, recipient: Recipient, registry: JWERegistry, cek: bytes):
    # https://www.rfc-editor.org/rfc/rfc7516#section-5
    headers = recipient.headers()
    registry.check_header(headers)

    # 1. Determine the Key Management Mode employed by the algorithm used
    # to determine the Content Encryption Key value.  (This is the
    # algorithm recorded in the "alg" (algorithm) Header Parameter of
    # the resulting JWE.)
    alg = registry.get_alg(headers["alg"])

    # 2. When Key Wrapping, Key Encryption, or Key Agreement with Key
    # Wrapping are employed, generate a random CEK value.  See RFC
    # 4086 [RFC4086] for considerations on generating random values.
    # The CEK MUST have a length equal to that required for the
    # content encryption algorithm.
    if not alg.direct_mode and not cek:
        cek = enc.generate_cek()

    # 3. When Direct Key Agreement or Key Agreement with Key Wrapping are
    # employed, use the key agreement algorithm to compute the value
    # of the agreed upon key.  When Direct Key Agreement is employed,
    # let the CEK be the agreed upon key.  When Key Agreement with Key
    # Wrapping is employed, the agreed upon key will be used to wrap
    # the CEK.
    if alg.key_agreement:
        if alg.direct_mode:
            recipient.encrypted_key = b""
            cek: bytes = alg.encrypt_agreed_upon_key(enc, recipient)
            if len(cek) * 8 != enc.cek_size:
                raise InvalidCEKLengthError(f"A key of size {enc.cek_size} bits MUST be used")
        else:
            agreed_upon_key = alg.encrypt_agreed_upon_key(enc, recipient)
            recipient.encrypted_key = alg.wrap_cek_with_auk(cek, agreed_upon_key)

    # 4. When Key Wrapping, Key Encryption, or Key Agreement with Key
    # Wrapping are employed, encrypt the CEK to the recipient and let
    # the result be the JWE Encrypted Key.
    elif not alg.direct_mode:
        recipient.encrypted_key = alg.encrypt_cek(cek, recipient)
    # 5. When Direct Key Agreement or Direct Encryption are employed, let
    # the JWE Encrypted Key be the empty octet sequence.
    else:
        recipient.encrypted_key = b""

    # 6. When Direct Encryption is employed, let the CEK be the shared
    # symmetric key.
    if isinstance(alg, JWEDirectEncryption):
        if cek:
            # TODO: direct mode only accept one recipient
            raise
        cek: bytes = alg.derive_cek(enc.cek_size, recipient)
    return cek


def decrypt_recipient(enc: JWEEncModel, recipient: Recipient, registry: JWERegistry):
    headers = recipient.headers()
    registry.check_header(headers, True)

    # Step 6, Determine the Key Management Mode employed by the algorithm
    # specified by the "alg" (algorithm) Header Parameter.
    alg = registry.get_alg(headers["alg"])

    # 7. Verify that the JWE uses a key known to the recipient.

    # 8. When Direct Key Agreement or Key Agreement with Key Wrapping are
    # employed, use the key agreement algorithm to compute the value
    # of the agreed upon key.  When Direct Key Agreement is employed,
    # let the CEK be the agreed upon key.  When Key Agreement with Key
    # Wrapping is employed, the agreed upon key will be used to
    # decrypt the JWE Encrypted Key.
    if alg.key_agreement:
        agreed_upon_key = alg.decrypt_agreed_upon_key(enc, recipient)
        if alg.direct_mode:
            cek = agreed_upon_key
            # step 10
            if recipient.encrypted_key:
                raise
        else:
            cek = alg.unwrap_cek_with_auk(recipient.encrypted_key, agreed_upon_key)
        return cek

    # 9. When Key Wrapping, Key Encryption, or Key Agreement with Key
    # Wrapping are employed, decrypt the JWE Encrypted Key to produce
    # the CEK.  The CEK MUST have a length equal to that required for
    # the content encryption algorithm.  Note that when there are
    # multiple recipients, each recipient will only be able to decrypt
    # JWE Encrypted Key values that were encrypted to a key in that
    # recipient's possession.  It is therefore normal to only be able
    # to decrypt one of the per-recipient JWE Encrypted Key values to
    # obtain the CEK value.
    elif not alg.direct_mode:
        cek = alg.decrypt_cek(recipient)
        if len(cek) * 8 != enc.cek_size:
            raise InvalidCEKLengthError(f"A key of size {enc.cek_size} bits MUST be used")

    # 10.  When Direct Key Agreement or Direct Encryption are employed,
    # verify that the JWE Encrypted Key value is an empty octet
    # sequence.
    # 11. When Direct Encryption is employed, let the CEK be the shared
    # symmetric key.
    else:
        if recipient.encrypted_key:
            raise
        cek = alg.derive_cek(enc.cek_size, recipient)
    return cek
