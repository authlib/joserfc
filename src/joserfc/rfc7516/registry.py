import typing as t
from .models import JWEAlgModel, JWEEncModel, JWEZipModel
from ..registry import (
    Header,
    HeaderRegistryDict,
    JWE_HEADER_REGISTRY,
    check_supported_header,
    check_registry_header,
    check_crit_header,
)

JWEAlgorithm = t.Union[JWEAlgModel, JWEEncModel, JWEZipModel]

AlgorithmsDict = t.TypedDict('AlgorithmsDict', {
    'alg': t.Dict[str, JWEAlgModel],
    'enc': t.Dict[str, JWEEncModel],
    'zip': t.Dict[str, JWEZipModel],
})
AlgorithmNamesDict = t.TypedDict('AlgorithmNamesDict', {
    'alg': t.List[str],
    'enc': t.List[str],
    'zip': t.List[str],
}, total=False)


class JWERegistry:
    algorithms: AlgorithmsDict = {
        'alg': {},
        'enc': {},
        'zip': {},
    }
    recommended: AlgorithmNamesDict = {
        'alg': [],
        'enc': [],
        'zip': [],
    }

    def __init__(
            self,
            headers: t.Optional[HeaderRegistryDict]=None,
            algorithms: t.Optional[AlgorithmNamesDict]=None,
            strict_check_header: bool=True):
        self.header_registry: HeaderRegistryDict = {}
        self.header_registry.update(JWE_HEADER_REGISTRY)
        if headers is not None:
            self.header_registry.update(headers)
        self.allowed = algorithms
        self.strict_check_header = strict_check_header

    @classmethod
    def register(cls, model: JWEAlgorithm):
        location = model.algorithm_location
        cls.algorithms[location][model.name] = model  # type: ignore
        if model.recommended:
            cls.recommended[location].append(model.name) # type: ignore

    def check_header(self, header: Header, check_more=False):
        check_crit_header(header)
        check_registry_header(self.header_registry, header)
        if check_more:
            alg = self.get_alg(header['alg'])
            if alg.more_header_registry:
                check_registry_header(alg.more_header_registry, header)
            if self.strict_check_header:
                allowed_registry = self.header_registry.copy()
                allowed_registry.update(alg.more_header_registry)
                check_supported_header(allowed_registry, header)
        elif self.strict_check_header:
            check_supported_header(self.header_registry, header)

    def get_alg(self, name: str) -> JWEAlgModel:
        return self._get_algorithm('alg', name)

    def get_enc(self, name: str) -> JWEEncModel:
        return self._get_algorithm('enc', name)

    def get_zip(self, name: str) -> JWEZipModel:
        return self._get_algorithm('zip', name)

    def _get_algorithm(self, location: str, name: str):
        if location not in self.algorithms:
            raise ValueError(f'Invalid location "{location}"')
        registry: t.Dict[str, JWEAlgorithm] = self.algorithms[location]  # type: ignore
        if name not in registry:
            raise ValueError(f'Algorithm of "{name}" is not supported')

        if self.allowed:
            allowed: t.List[str] = self.allowed[location] # type: ignore
        else:
            allowed: t.List[str] = self.recommended[location] # type: ignore

        if name not in allowed:
            raise ValueError(f'Algorithm of "{name}" is not allowed')
        return registry[name]


default_registry = JWERegistry()
