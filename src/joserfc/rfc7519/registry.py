from typing import Optional, List
from .validators import JWTClaimsRequests
from .claims import Claims
from ..registry import HeaderRegistryDict
from ..rfc7515.registry import JWSRegistry


class JWTRegistry(JWSRegistry):
    def __init__(
            self,
            headers: Optional[HeaderRegistryDict]=None,
            algorithms: Optional[List[str]]=None,
            claims: Optional[JWTClaimsRequests]=None):
        super().__init__(headers, algorithms)
        self.claims = claims

    def check_claims(self, claims: Claims):
        if self.claims:
            self.claims.validate(claims)


default_registry = JWTRegistry()
