from typing import Dict, List, Optional
from .model import JWSAlgModel
from .._registry import (
    JWS_HEADER_REGISTRY,
    Header,
    HeaderParameter,
    HeaderRegistryDict,
    check_crit,
)


class JWSRegistry(object):
    algorithms: Dict[str, JWSAlgModel] = {}
    recommended_algorithms: List[str] = []

    def __init__(self, headers: Optional[HeaderRegistryDict]=None, algorithms: Optional[List[str]]=None):
        self.headers: Dict[str, HeaderParameter] = {}
        self.headers.update(JWS_HEADER_REGISTRY)
        if headers is not None:
            self.headers.update(headers)
        self.allowed_algorithms = algorithms

    @classmethod
    def register(cls, alg: JWSAlgModel):
        cls.algorithms[alg.name] = alg
        if alg.recommended:
            cls.recommended_algorithms.append(alg.name)

    def get_alg(self, name: str):
        if name not in self.algorithms:
            raise ValueError(f'Algorithm of "{name}" is not supported')
        if self.allowed_algorithms:
            allowed = self.allowed_algorithms
        else:
            allowed = self.recommended_algorithms

        if name not in allowed:
            raise ValueError(f'Algorithm of "{name}" is not allowed')
        return self.algorithms[name]

    def check_header(self, header: Header):
        allowed_keys = set(self.headers.keys())
        unsupported_keys = set(header.keys()) - allowed_keys
        if unsupported_keys:
            raise ValueError(f'Unsupported "{unsupported_keys} in header')

        # check crit header
        if 'crit' in header:
            check_crit(header)

        for key in self.headers:
            reg: HeaderParameter = self.headers[key]
            if reg.required and key not in header:
                raise ValueError(f'Required "{key}" is missing in header')
            if key in header:
                reg.check_value(key, header[key])


#: default JWS registry
default_registry = JWSRegistry()
