import time
from typing import TypedDict, Optional, Union, List, Dict, Any
from ..errors import (
    MissingClaimError,
    InvalidClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


#: http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
ClaimsOption = TypedDict('ClaimsOption', {
    'essential': bool,
    'value': Union[str, int],
    'values': List[Union[str, int]],
})


class ClaimsRequests:
    """Requesting "claims" for JWT with the given conditions."""

    def __init__(self, **kwargs: ClaimsOption):
        self.options = kwargs

    def check_value(self, claim_name: str, value: Any):
        option: ClaimsOption = self.options.get(claim_name)
        option_value = option.get('value')
        if option_value and value != option_value:
            raise InvalidClaimError(claim_name)

        option_values = option.get('values')
        if option_values and value not in option_values:
            raise InvalidClaimError(claim_name)

    def validate(self, claims: Dict[str, Any]):
        for key in self.options:
            option: ClaimsOption = self.options[key]
            if key not in claims:
                # validate essential claims
                if option.get('essential'):
                    raise MissingClaimError(key)
            else:
                value = claims[key]
                func = getattr(self, 'validate_' + key, None)
                if func:
                    func(value)
                else:
                    self.check_value(key, value)


class JWTClaimsRequests(ClaimsRequests):
    def __init__(self, now: Optional[int]=None, leeway=0, **kwargs: ClaimsOption):
        if now is None:
            now = int(time.time())
        self.now = now
        self.leeway = leeway
        super().__init__(**kwargs)

    def validate_aud(self, value):
        """The "aud" (audience) claim identifies the recipients that the JWT is
        intended for.  Each principal intended to process the JWT MUST
        identify itself with a value in the audience claim.  If the principal
        processing the claim does not identify itself with a value in the
        "aud" claim when this claim is present, then the JWT MUST be
        rejected.  In the general case, the "aud" value is an array of case-
        sensitive strings, each containing a StringOrURI value.  In the
        special case when the JWT has one audience, the "aud" value MAY be a
        single case-sensitive string containing a StringOrURI value.  The
        interpretation of audience values is generally application specific.
        Use of this claim is OPTIONAL.
        """
        option: ClaimsOption = self.options['aud']
        option_values = option.get('values')

        if not option_values:
            option_value = option.get('value')
            if option_value:
                option_values = option_value

        if not option_values:
            return

        if isinstance(value, list):
            aud_list = value
        else:
            aud_list = [value]

        if not any([v in aud_list for v in option_values]):
            raise InvalidClaimError('aud')

    def validate_exp(self, value: int):
        """The "exp" (expiration time) claim identifies the expiration time on
        or after which the JWT MUST NOT be accepted for processing.  The
        processing of the "exp" claim requires that the current date/time
        MUST be before the expiration date/time listed in the "exp" claim.
        Implementers MAY provide for some small leeway, usually no more than
        a few minutes, to account for clock skew.  Its value MUST be a number
        containing a NumericDate value.  Use of this claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError('exp')
        if value < (self.now - self.leeway):
            raise ExpiredTokenError()
        self.check_value('exp', value)

    def validate_nbf(self, value: int):
        """The "nbf" (not before) claim identifies the time before which the JWT
        MUST NOT be accepted for processing.  The processing of the "nbf"
        claim requires that the current date/time MUST be after or equal to
        the not-before date/time listed in the "nbf" claim.  Implementers MAY
        provide for some small leeway, usually no more than a few minutes, to
        account for clock skew.  Its value MUST be a number containing a
        NumericDate value.  Use of this claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError('nbf')
        if value > (self.now + self.leeway):
            raise InvalidTokenError()
        self.check_value('nbf', value)

    def validate_iat(self, value: int):
        """The "iat" (issued at) claim identifies the time at which the JWT was
        issued.  This claim can be used to determine the age of the JWT.  Its
        value MUST be a number containing a NumericDate value.  Use of this
        claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError('iat')
        self.check_value('iat', value)


def _validate_numeric_time(s):
    return isinstance(s, (int, float))
