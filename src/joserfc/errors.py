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


class BadSignatureError(JoseError):
    error: str = 'bad_signature'


class InvalidUseError(JoseError):
    error: str = 'invalid_use'
    description: str = 'Key "use" is not valid for your usage'


class InvalidClaimError(JoseError):
    error = 'invalid_claim'

    def __init__(self, claim):
        description = f'Invalid claim: "{claim}"'
        super(InvalidClaimError, self).__init__(description=description)


class MissingClaimError(JoseError):
    error = 'missing_claim'

    def __init__(self, claim):
        description = f'Missing claim: "{claim}"'
        super(MissingClaimError, self).__init__(description=description)


class InsecureClaimError(JoseError):
    error = 'insecure_claim'

    def __init__(self, claim):
        description = f'Insecure claim "{claim}"'
        super(InsecureClaimError, self).__init__(description=description)


class ExpiredTokenError(JoseError):
    error = 'expired_token'
    description = 'The token is expired'


class InvalidTokenError(JoseError):
    error = 'invalid_token'
    description = 'The token is not valid yet'
