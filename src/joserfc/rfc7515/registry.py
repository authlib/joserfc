from typing import Dict, List, Optional
from .model import JWSAlgModel
from .._registry import (
    JWS_HEADER_REGISTRY,
    Header,
    HeaderRegistryDict,
    check_header,
)


class JWSRegistry(object):
    algorithms: Dict[str, JWSAlgModel] = {}
    recommended: List[str] = []

    def __init__(self, headers: Optional[HeaderRegistryDict]=None, algorithms: Optional[List[str]]=None):
        self.headers: HeaderRegistryDict = {}
        self.headers.update(JWS_HEADER_REGISTRY)
        if headers is not None:
            self.headers.update(headers)
        self.allowed = algorithms

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
        check_header(self.headers, header)


#: default JWS registry
default_registry = JWSRegistry()
