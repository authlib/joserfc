from .._rfc7516.compact import *  # noqa: F403
import warnings

warnings.warn(
    "Please import from joserfc.jwe module, as this module will be removed in version 1.4.0.",
    DeprecationWarning,
    stacklevel=2,
)
