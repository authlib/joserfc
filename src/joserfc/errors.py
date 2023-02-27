from typing import Optional


class JoseError(Exception):
    """Base Exception for all errors in joserfc."""

    #: short-string error code
    error: str = ''
    #: long-string to describe this error
    description: str = ''

    def __init__(self, description: Optional[str]=None, error: Optional[str]=None):
        if error is not None:
            self.error = error
        if description is not None:
            self.description = description

        message = '{}: {}'.format(self.error, self.description)
        super(JoseError, self).__init__(message)

    def __repr__(self):
        return '<{} "{}">'.format(self.__class__.__name__, self.error)


class DecodeError(JoseError):
    error: str = 'decode_error'


class MissingAlgorithmError(JoseError):
    error: str = 'missing_algorithm'
    description: str = 'Missing "alg" value in header'


class MissingEncryptionError(JoseError):
    error: str = 'missing_encryption'
    description: str = 'Missing "enc" value in header'


class InvalidKeyManagementModeError(JoseError):
    error: str = 'invalid_key_management_mode'
    description: str = ''


class BadSignatureError(JoseError):
    error: str = 'bad_signature'


class InvalidClaimError(JoseError):
    error: str = 'invalid_claim'

    def __init__(self, claim):
        description = f'Invalid claim: "{claim}"'
        super(InvalidClaimError, self).__init__(description=description)


class MissingClaimError(JoseError):
    error: str = 'missing_claim'

    def __init__(self, claim):
        description = f'Missing claim: "{claim}"'
        super(MissingClaimError, self).__init__(description=description)


class InsecureClaimError(JoseError):
    error: str = 'insecure_claim'

    def __init__(self, claim):
        description = f'Insecure claim "{claim}"'
        super(InsecureClaimError, self).__init__(description=description)


class ExpiredTokenError(JoseError):
    error: str = 'expired_token'
    description: str = 'The token is expired'


class InvalidTokenError(JoseError):
    error: str = 'invalid_token'
    description: str = 'The token is not valid yet'


class InvalidTypeError(JoseError):
    error: str = 'invalid_type'
    description: str = 'The "typ" value in header is invalid'


class InvalidPayloadError(JoseError):
    error: str = 'invalid_payload'
