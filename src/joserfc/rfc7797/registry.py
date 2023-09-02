from ..registry import JWS_HEADER_REGISTRY, Header, HeaderParameter
from ..rfc7515.registry import JWSRegistry as _JWSRegistry


class JWSRegistry(_JWSRegistry):
    default_header_registry = {
        "b64": HeaderParameter("JWS Signing Input Formula", "bool"),
        **JWS_HEADER_REGISTRY,
    }

    def check_header(self, header: Header) -> None:
        if "b64" in header:
            _safe_b64_header(header)
        super(JWSRegistry, self).check_header(header)


def _safe_b64_header(header: Header) -> bool:
    # https://datatracker.ietf.org/doc/html/rfc7797#section-6
    crit = header.get("crit")
    if isinstance(crit, list) and "b64" in crit:
        return True
    raise ValueError('The "crit" Header Parameter MUST be included with "b64"')
