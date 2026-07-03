import time
import json
import datetime
import calendar
from json import JSONEncoder
from typing import TypedDict, Any, Callable
from ..util import to_bytes
from ..errors import (
    MissingClaimError,
    InvalidClaimError,
    ExpiredTokenError,
)

Claims = dict[str, Any]


def convert_claims(claims: Claims, encoder_cls: type[JSONEncoder] | None = None) -> bytes:
    """Turn claims into bytes payload."""
    for k in ["exp", "iat", "nbf"]:
        claim = claims.get(k)
        if isinstance(claim, datetime.datetime):
            claims[k] = calendar.timegm(claim.utctimetuple())

    content = json.dumps(claims, ensure_ascii=False, separators=(",", ":"), cls=encoder_cls)
    return to_bytes(content)


#: http://openid.net/specs/openid-connect-core-1_0.html#IndividualClaimsRequests
class ClaimsOption(TypedDict, total=False):
    essential: bool
    allow_blank: bool | None
    value: str | int | bool
    values: list[str | int | bool] | list[str] | list[int] | list[bool]


class BaseClaimsRegistry:
    """Requesting "claims" for JWT with the given conditions."""

    def __init__(self, **kwargs: ClaimsOption):
        self.options = kwargs

    @property
    def essential_keys(self) -> set[str]:
        """Returns the essential claim names."""
        return {key for key in self.options if self.options[key].get("essential")}

    def check_value(self, claim_name: str, value: Any) -> None:
        """
        Validates a given claim value based on predefined options.

        :param claim_name: The name of the claim to validate.
        :param value: The value of the claim to be validated.
        :raises InvalidClaimError: If the value does not meet the claim's validation requirements.
        """
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
        """
        Validates the provided claims against specified requirements and checks.

        :param claims: A dictionary containing claims to validate.
        :raises InvalidClaimError: Raised if any claim fails validation.
        :raises MissingClaimError: Raised if one or more essential keys are missing.
        """
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


class JWTClaimsRegistry(BaseClaimsRegistry):
    """A claims registry for validating JWT claims.

    :param now: timestamp of "now" time
    :param leeway: leeway time in seconds
    :param kwargs: claims options
    """

    def __init__(self, now: int | Callable[[], int] | None = None, leeway: int = 0, **kwargs: ClaimsOption) -> None:
        if now is None:
            now = _generate_now
        self._now = now
        self.leeway = leeway
        super().__init__(**kwargs)

    @property
    def now(self) -> int:
        """Returns the current timestamp."""
        if callable(self._now):
            return self._now()
        return self._now

    def validate_iss(self, value: str) -> None:
        """The "iss" (issuer) claim identifies the principal that issued the
        JWT.  The processing of this claim is generally application specific.
        The "iss" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        """
        if not isinstance(value, str):
            raise InvalidClaimError("str", "Claim 'str' must be a StringOrURI value")
        self.check_value("iss", value)

    def validate_sub(self, value: str) -> None:
        """The "sub" (subject) claim identifies the principal that is the
        subject of the JWT.  The claims in a JWT are normally statements
        about the subject.  The subject value MUST either be scoped to be
        locally unique in the context of the issuer or be globally unique.
        The processing of this claim is generally application specific.  The
        "sub" value is a case-sensitive string containing a StringOrURI
        value.  Use of this claim is OPTIONAL.
        """
        if not isinstance(value, str):
            raise InvalidClaimError("sub", "Claim 'sub' must be a StringOrURI value")
        self.check_value("sub", value)

    def validate_aud(self, value: str | list[str]) -> None:
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
        if isinstance(value, str) or _validate_list_of_strings(value):
            self.check_value("aud", value)
        else:
            raise InvalidClaimError(
                "aud", "Claim 'aud' must be an array of StringOrURI value or a single StringOrURI value"
            )

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
            raise InvalidClaimError("exp", "Claim 'exp' must be a NumericDate value")
        if value < (self.now - self.leeway):
            raise ExpiredTokenError("exp")
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
            raise InvalidClaimError("nbf", "Claim 'nbf' must be a NumericDate value")
        if value > (self.now + self.leeway):
            raise InvalidClaimError("nbf", "The token is not yet valid")
        self.check_value("nbf", value)

    def validate_iat(self, value: int) -> None:
        """The "iat" (issued at) claim identifies the time at which the JWT was
        issued.  This claim can be used to determine the age of the JWT.  Its
        value MUST be a number containing a NumericDate value.  Use of this
        claim is OPTIONAL.
        """
        if not _validate_numeric_time(value):
            raise InvalidClaimError("iat", "Claim 'iat' must be a NumericDate value")
        if value > (self.now + self.leeway):
            raise InvalidClaimError("iat", "The token was issued in the future")
        self.check_value("iat", value)


def _validate_numeric_time(s: int) -> bool:
    return isinstance(s, (int, float))


def _validate_list_of_strings(s: list[str]) -> bool:
    return isinstance(s, list) and all(isinstance(v, str) for v in s)


def _generate_now() -> int:
    return int(time.time())
