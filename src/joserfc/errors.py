from __future__ import annotations


class JoseError(Exception):
    """Base Exception for all errors in joserfc."""

    #: short-string error code
    error: str = ""
    #: long-string to describe this error
    description: str = ""

    def __init__(self, description: str | None = None):
        if description is not None:
            self.description = description

        message = "{}: {}".format(self.error, self.description)
        super(JoseError, self).__init__(message)


class DecodeError(JoseError):
    error = "decode_error"


class UnsupportedKeyUseError(JoseError):
    error = "unsupported_key_use"


class UnsupportedKeyAlgorithmError(JoseError):
    error = "unsupported_key_alg"


class UnsupportedKeyOperationError(JoseError):
    error = "unsupported_key_operation"


class InvalidKeyLengthError(JoseError):
    error = "invalid_key_length"


class InvalidKeyTypeError(JoseError):
    error = "invalid_key_type"


class InvalidExchangeKeyError(JoseError):
    error = "invalid_exchange_key"
    description = "Invalid key for exchanging shared key"


class InvalidEncryptedKeyError(JoseError):
    error = "invalid_encrypted_key"
    description = "JWE Encrypted Key value SHOULD be an empty octet sequence"


class MissingAlgorithmError(JoseError):
    error = "missing_algorithm"
    description = 'Missing "alg" value in header'


class ConflictAlgorithmError(JoseError):
    error = "conflict_algorithm"


class MissingEncryptionError(JoseError):
    error = "missing_encryption"
    description = 'Missing "enc" value in header'


class BadSignatureError(JoseError):
    """This error is designed for JWS/JWT. It is raised when signature
    does not match.
    """
    error = "bad_signature"


class ExceededSizeError(JoseError):
    """This error is designed for DEF zip algorithm. It raised when the
    compressed data exceeds the maximum allowed length."""
    error = "exceeded_size"


class InvalidEncryptionAlgorithmError(JoseError):
    """This error is designed for JWE. It is raised when "enc" value
    does not work together with "alg" value.
    """
    error = 'invalid_encryption_algorithm'


class InvalidCEKLengthError(JoseError):
    error = "invalid_cek_length"
    description = 'Invalid "cek" length'


class InvalidClaimError(JoseError):
    error = "invalid_claim"

    def __init__(self, claim: str):
        description = f'Invalid claim: "{claim}"'
        super(InvalidClaimError, self).__init__(description=description)


class MissingClaimError(JoseError):
    error = "missing_claim"

    def __init__(self, claim: str):
        description = f'Missing claim: "{claim}"'
        super(MissingClaimError, self).__init__(description=description)


class InsecureClaimError(JoseError):
    error = "insecure_claim"

    def __init__(self, claim: str):
        description = f'Insecure claim "{claim}"'
        super(InsecureClaimError, self).__init__(description=description)


class ExpiredTokenError(JoseError):
    error = "expired_token"
    description = "The token is expired"


class InvalidTokenError(JoseError):
    error = "invalid_token"
    description = "The token is not valid yet"


class InvalidPayloadError(JoseError):
    error = "invalid_payload"
