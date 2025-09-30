from __future__ import annotations


class SecurityWarning(UserWarning):
    """Base class for warnings of security issues."""

    pass


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
    """This error is designed for JWS/JWE. It is raised when deserialization
    and decryption fails.
    """

    error = "decode_error"


class MissingKeyError(JoseError):
    error = "missing_key"


class UnsupportedKeyUseError(JoseError):
    error = "unsupported_key_use"


class UnsupportedKeyAlgorithmError(JoseError):
    error = "unsupported_key_alg"


class UnsupportedKeyOperationError(JoseError):
    error = "unsupported_key_operation"


class InvalidKeyLengthError(JoseError):
    error = "invalid_key_length"


class MissingKeyTypeError(JoseError):
    error = "missing_key_type"


class InvalidKeyTypeError(JoseError):
    error = "invalid_key_type"


class InvalidKeyCurveError(JoseError):
    error = "invalid_key_curve"


class InvalidKeyIdError(JoseError):
    error = "invalid_key_id"


class InvalidExchangeKeyError(JoseError):
    error = "invalid_exchange_key"
    description = "Invalid key for exchanging shared key"


class InvalidEncryptedKeyError(JoseError):
    error = "invalid_encrypted_key"
    description = "JWE Encrypted Key value SHOULD be an empty octet sequence"


class MissingAlgorithmError(JoseError):
    error = "missing_algorithm"
    description = "Missing 'alg' value in header"


class ConflictAlgorithmError(JoseError):
    error = "conflict_algorithm"


class UnsupportedAlgorithmError(JoseError):
    error = "unsupported_algorithm"


class InvalidHeaderValueError(JoseError):
    error = "invalid_header_value"


class UnsupportedHeaderError(JoseError):
    error = "unsupported_header"


class MissingHeaderError(JoseError):
    """This error happens when the required header does not exist."""

    error = "missing_header"

    def __init__(self, key: str):
        description = f"Missing '{key}' value in header"
        super(MissingHeaderError, self).__init__(description=description)


class MissingCritHeaderError(JoseError):
    """This error happens when the critical header does not exist."""

    error = "missing_crit_header"

    def __init__(self, key: str):
        description = f"Missing critical '{key}' value in header"
        super(MissingCritHeaderError, self).__init__(description=description)


class MissingEncryptionError(JoseError):
    """This error is designed for JWE. It is raised when the 'enc' value
    in header is missing."""

    error = "missing_encryption"
    description = "Missing 'enc' value in header"


class BadSignatureError(JoseError):
    """This error is designed for JWS/JWT. It is raised when signature
    does not match.
    """

    error = "bad_signature"


class ExceededSizeError(JoseError):
    """This error is designed for validating the token's content size.
    It raised when the data exceeds the maximum allowed length."""

    error = "exceeded_size"


class InvalidEncryptionAlgorithmError(JoseError):
    """This error is designed for JWE. It is raised when "enc" value
    does not work together with "alg" value.
    """

    error = "invalid_encryption_algorithm"


class InvalidCEKLengthError(JoseError):
    error = "invalid_cek_length"
    description = "Invalid 'cek' length"

    def __init__(self, cek_size: int):  # pragma: no cover
        description = f"A key of size {cek_size} bits MUST be used"
        super(InvalidCEKLengthError, self).__init__(description=description)


class InvalidClaimError(JoseError):
    """This error is designed for JWT. It raised when the claim contains
    invalid values or types."""

    claim: str
    error = "invalid_claim"

    def __init__(self, claim: str):
        self.claim = claim
        description = f"Invalid claim: '{claim}'"
        super(InvalidClaimError, self).__init__(description=description)


class MissingClaimError(JoseError):
    """This error is designed for JWT. It raised when the required
    claims are missing."""

    claim: str
    error = "missing_claim"

    def __init__(self, claim: str):
        self.claim = claim
        description = f"Missing claim: '{claim}'"
        super(MissingClaimError, self).__init__(description=description)


class InsecureClaimError(JoseError):
    """This error is designed for JWT. It raised when the claim
    contains sensitive information."""

    claim: str
    error = "insecure_claim"

    def __init__(self, claim: str):
        self.claim = claim
        description = f"Insecure claim '{claim}'"
        super(InsecureClaimError, self).__init__(description=description)


class ExpiredTokenError(JoseError):
    """This error is designed for JWT. It raised when the token is expired."""

    error = "expired_token"
    description = "The token is expired"


class InvalidTokenError(JoseError):
    """This error is designed for JWT. It raised when the token is not valid yet."""

    error = "invalid_token"
    description = "The token is not valid yet"


class InvalidPayloadError(JoseError):
    """This error is designed for JWT. It raised when the payload is
    not a valid JSON object."""

    error = "invalid_payload"
