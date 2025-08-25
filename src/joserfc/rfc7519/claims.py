from .._rfc7519.claims import convert_claims  # noqa: F403
from .._rfc7519.security import check_sensitive_data  # noqa: F403
import warnings

warnings.warn(
    "Please import from joserfc.jwt module, as this module will be removed in version 1.4.0.",
    DeprecationWarning,
    stacklevel=2,
)
