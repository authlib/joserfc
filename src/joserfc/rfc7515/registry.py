from __future__ import annotations
from typing import Dict
from .model import JWSAlgModel
from ..registry import (
    JWS_HEADER_REGISTRY,
    Header,
    HeaderRegistryDict,
    validate_registry_header,
    check_crit_header,
    check_supported_header,
)


class JWSRegistry:
    """A registry for JSON Web Signature to keep all the supported algorithms.
    An instance of ``JWSRegistry`` is usually used together with methods in
    ``joserfc.jws``.

    :param header_registry: extra header parameters registry
    :param algorithms: allowed algorithms to be used
    :param strict_check_header: only allow header key in the registry to be used
    """
    default_header_registry: HeaderRegistryDict = JWS_HEADER_REGISTRY
    algorithms: Dict[str, JWSAlgModel] = {}
    recommended: list[str] = []

    def __init__(
            self,
            header_registry: HeaderRegistryDict | None = None,
            algorithms: list[str] | None = None,
            strict_check_header: bool = True):
        self.header_registry: HeaderRegistryDict = {}
        self.header_registry.update(self.default_header_registry)
        if header_registry is not None:
            self.header_registry.update(header_registry)
        self.allowed = algorithms
        self.strict_check_header = strict_check_header

    @classmethod
    def register(cls, alg: JWSAlgModel) -> None:
        """Register a given JWS algorithm instance to the registry."""
        cls.algorithms[alg.name] = alg
        if alg.recommended:
            cls.recommended.append(alg.name)

    def get_alg(self, name: str) -> JWSAlgModel:
        """Get the allowed algorithm instance of the given name.

        :param name: value of the ``alg``, e.g. ``HS256``, ``RS256``
        """
        if name not in self.algorithms:
            raise ValueError(f'Algorithm of "{name}" is not supported')
        if self.allowed:
            allowed = self.allowed
        else:
            allowed = self.recommended

        if name not in allowed:
            raise ValueError(f'Algorithm of "{name}" is not allowed')
        return self.algorithms[name]

    def check_header(self, header: Header) -> None:
        """Check and validate the fields in header part of a JWS object."""
        check_crit_header(header)
        validate_registry_header(self.header_registry, header)
        if self.strict_check_header:
            check_supported_header(self.header_registry, header)


#: default JWS registry
default_registry = JWSRegistry()


def construct_registry(algorithms: list[str] | None = None) -> JWSRegistry:
    if algorithms:
        registry = JWSRegistry(algorithms=algorithms)
    else:
        registry = default_registry
    return registry
