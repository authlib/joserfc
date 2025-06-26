from .._rfc7515.registry import *  # noqa: F403
import warnings

warnings.warn(
    "Please import from joserfc.jws module, as this module will be removed in version 1.4.0.",
    DeprecationWarning,
    stacklevel=2,
)
