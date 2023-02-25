import typing as t
from .models import JWEAlgModel, JWEEncModel, JWEZipModel
from ..registry import (
    Header,
    HeaderRegistryDict,
    JWE_HEADER_REGISTRY,
    check_header,
    check_registry_header,
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
            algorithms: t.Optional[AlgorithmNamesDict]=None):
        self.headers: HeaderRegistryDict = {}
        self.headers.update(JWE_HEADER_REGISTRY)
        if headers is not None:
            self.headers.update(headers)
        self.allowed = algorithms

    @classmethod
    def register(cls, model: JWEAlgorithm):
        location = model.algorithm_location
        cls.algorithms[location][model.name] = model  # type: ignore
        if model.recommended:
            cls.recommended[location].append(model.name) # type: ignore

    def check_header(self, header: Header, check_extra=False):
        if check_extra:
            check_header(self.headers, header, False)
            alg = self.get_alg(header['alg'])
            if alg.extra_headers:
                check_registry_header(alg.extra_headers, header)
        else:
            check_header(self.headers, header, True)

    def get_alg(self, name: str) -> JWEAlgModel:
        return self._get_algorithm('alg', name)

    def get_enc(self, name: str) -> JWEEncModel:
        return self._get_algorithm('enc', name)

    def get_zip(self, name: str) -> JWEZipModel:
        return self._get_algorithm('zip', name)

    def get_algorithms(self, header: Header) -> t.Tuple[JWEAlgModel, JWEEncModel, t.Optional[JWEZipModel]]:
        alg = self.get_alg(header['alg'])
        enc = self.get_enc(header['enc'])
        if 'zip' in header:
            zip_ = self.get_zip(header['zip'])
        else:
            zip_ = None
        return alg, enc, zip_

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
