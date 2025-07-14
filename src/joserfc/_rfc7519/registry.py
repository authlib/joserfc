from __future__ import annotations
import time
from typing import TypedDict, Any
from ..errors import (
    MissingClaimError,
    InvalidClaimError,
    ExpiredTokenError,
    InvalidTokenError,
)


#: http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
class ClaimsOption(TypedDict, total=False):
    essential: bool
    allow_blank: bool | None
    value: str | int | bool
    values: list[str | int | bool] | list[str] | list[int] | list[bool]


class ClaimsRegistry:
    """Requesting "claims" for JWT with the given conditions."""

    def __init__(self, **kwargs: ClaimsOption):
        self.options = kwargs
        self.essential_keys = {key for key in kwargs if kwargs[key].get("essential")}

    def check_value(self, claim_name: str, value: Any) -> None:
        option = self.options.get(claim_name)
        if not option:
            return

        allow_blank = option.get("allow_blank")
        if not allow_blank and value in (None, "", [], {}):
            raise InvalidClaimError(claim_name)

        option_values = option.get("values")

        if option_values is None:
            option_value = option.get("value")
            if option_value is not None:
                option_values = [option_value]

        if not option_values:
            return

        if isinstance(value, list):
            if not any(v in value for v in option_values):
                raise InvalidClaimError(claim_name)
        else:
            if value not in option_values:
                raise InvalidClaimError(claim_name)

    def validate(self, claims: dict[str, Any]) -> None:
        missed_keys = {key for key in self.essential_keys if claims.get(key) is None}
        if missed_keys:
            raise MissingClaimError(",".join(sorted(missed_keys)))

        for key in claims:
            value = claims[key]
            func = getattr(self, "validate_" + key, None)
            if func:
                func(value)
            elif key in self.options:
                self.check_value(key, value)


class JWTClaimsRegistry(ClaimsRegistry):
    def __init__(self, now: int | None = None, leeway: int = 0, **kwargs: ClaimsOption):
        if now is None:
            now = int(time.time())
        self.now = now
        self.leeway = leeway
        super().__init__(**kwargs)

    def validate_exp(self, value: int) -> None:
        """The "exp" (expiration time) claim identifies the expiration time on
        or after which the JWT MUST NOT be accepted for processing.  The
        processing of the "exp" claim requires that the current date/time
        MUST be before the expiration date/time listed in the "exp" claim.
        Implementers MAY provide for some small leeway, usually no more than
        a few minutes, to account for clock skew.  Its value MUST be a number
        containing a NumericDate value.  Use of this claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError("exp")
        if value < (self.now - self.leeway):
            raise ExpiredTokenError()
        self.check_value("exp", value)

    def validate_nbf(self, value: int) -> None:
        """The "nbf" (not before) claim identifies the time before which the JWT
        MUST NOT be accepted for processing.  The processing of the "nbf"
        claim requires that the current date/time MUST be after or equal to
        the not-before date/time listed in the "nbf" claim.  Implementers MAY
        provide for some small leeway, usually no more than a few minutes, to
        account for clock skew.  Its value MUST be a number containing a
        NumericDate value.  Use of this claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError("nbf")
        if value > (self.now + self.leeway):
            raise InvalidTokenError()
        self.check_value("nbf", value)

    def validate_iat(self, value: int) -> None:
        """The "iat" (issued at) claim identifies the time at which the JWT was
        issued.  This claim can be used to determine the age of the JWT.  Its
        value MUST be a number containing a NumericDate value.  Use of this
        claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError("iat")
        if value > (self.now + self.leeway):
            raise InvalidTokenError()
        self.check_value("iat", value)


def _validate_numeric_time(s: int) -> bool:
    return isinstance(s, (int, float))
