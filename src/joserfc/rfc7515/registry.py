from typing import Dict, List, Optional
from .model import JWSAlgModel
from ..registry import (
    JWS_HEADER_REGISTRY,
    Header,
    HeaderRegistryDict,
    check_registry_header,
    check_crit_header,
    check_supported_header,
)


class JWSRegistry(object):
    algorithms: Dict[str, JWSAlgModel] = {}
    recommended: List[str] = []

    def __init__(
            self,
            headers: Optional[HeaderRegistryDict]=None,
            algorithms: Optional[List[str]]=None,
            strict_check_header: bool=True):
        self.header_registry: HeaderRegistryDict = {}
        self.header_registry.update(JWS_HEADER_REGISTRY)
        if headers is not None:
            self.header_registry.update(headers)
        self.allowed = algorithms
        self.strict_check_header = strict_check_header

    @classmethod
    def register(cls, alg: JWSAlgModel):
        cls.algorithms[alg.name] = alg
        if alg.recommended:
            cls.recommended.append(alg.name)

    def get_alg(self, name: str):
        if name not in self.algorithms:
            raise ValueError(f'Algorithm of "{name}" is not supported')
        if self.allowed:
            allowed = self.allowed
        else:
            allowed = self.recommended

        if name not in allowed:
            raise ValueError(f'Algorithm of "{name}" is not allowed')
        return self.algorithms[name]

    def check_header(self, header: Header):
        check_crit_header(header)
        check_registry_header(self.header_registry, header)
        if self.strict_check_header:
            check_supported_header(self.header_registry, header)


#: default JWS registry
default_registry = JWSRegistry()
