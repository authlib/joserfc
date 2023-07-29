import re
import datetime
import calendar
from typing import Dict, Any
from ..util import to_bytes, json_dumps
from ..errors import InsecureClaimError


SENSITIVE_NAMES = ("password", "token", "secret", "secret_key", "api_key")
SENSITIVE_VALUES = re.compile(
    r"|".join([
        # http://www.richardsramblings.com/regex/credit-card-numbers/
        r"\b(?:3[47]\d|(?:4\d|5[1-5]|65)\d{2}|6011)\d{12}\b",
        # various private keys
        r"-----BEGIN[A-Z ]+PRIVATE KEY-----.+-----END[A-Z ]+PRIVATE KEY-----",
        # social security numbers (US)
        r"^\b(?!(000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    ]),
    re.DOTALL,
)

Claims = Dict[str, Any]


def convert_claims(claims: Claims) -> bytes:
    """Turn claims into bytes payload."""
    for k in ["exp", "iat", "nbf"]:
        claim = claims.get(k)
        if isinstance(claim, datetime.datetime):
            claims[k] = calendar.timegm(claim.utctimetuple())
    return to_bytes(json_dumps(claims))


def check_sensitive_data(claims: Claims) -> None:
    """Check if claims contains sensitive information."""
    for k in claims:
        # check claims key name
        if k in SENSITIVE_NAMES:
            raise InsecureClaimError(k)

        # check claims values
        v = claims[k]
        if isinstance(v, str) and SENSITIVE_VALUES.search(v):
            raise InsecureClaimError(k)
