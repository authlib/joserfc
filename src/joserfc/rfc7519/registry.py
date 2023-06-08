from typing import Optional, List
from .validators import JWTClaimsRequests
from .claims import Claims
from ..registry import HeaderRegistryDict
from ..rfc7515.registry import JWSRegistry


class JWTRegistry(JWSRegistry):
    """A registry for JSON Web Token to keep all the supported algorithms.
    An instance of ``JWTRegistry`` is usually used together with methods in
    :module:`joserfc.jwt`.

    :param headers: extra header parameter definitions
    :param algorithms: allowed algorithms to be used
    :param claims: an instance of claims validator
    :param strict_check_header: only allow header key in the registry to be used
    """
    def __init__(
            self,
            headers: Optional[HeaderRegistryDict] = None,
            algorithms: Optional[List[str]] = None,
            claims: Optional[JWTClaimsRequests] = None,
            strict_check_header: bool = True):
        super().__init__(headers, algorithms, strict_check_header)
        self.claims = claims

    def check_claims(self, claims: Claims):
        """Check and validate the fields in payload claims part of a JWT object."""
        if self.claims:
            self.claims.validate(claims)


default_registry = JWTRegistry()
