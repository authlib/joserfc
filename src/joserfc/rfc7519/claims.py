from .._rfc7519.claims import *  # noqa: F403
import warnings

warnings.warn(
    "Please import from joserfc.jwt module, as this module will be removed in version 1.4.0.",
    DeprecationWarning,
    stacklevel=2,
)
