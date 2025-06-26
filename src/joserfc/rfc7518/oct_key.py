from .._rfc7518.oct_key import *
import warnings

warnings.warn(
    "Please import from joserfc.jwk module, as this module will be removed in version 1.4.0.",
    DeprecationWarning,
    stacklevel=2,
)
