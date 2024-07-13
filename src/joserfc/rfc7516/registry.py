from __future__ import annotations
import typing as t
from .models import JWEAlgModel, JWEEncModel, JWEZipModel
from ..registry import (
    Header,
    HeaderRegistryDict,
    JWE_HEADER_REGISTRY,
    check_supported_header,
    validate_registry_header,
    check_crit_header,
)

JWEAlgorithm = t.Union[JWEAlgModel, JWEEncModel, JWEZipModel]

AlgorithmsDict = t.TypedDict("AlgorithmsDict", {
    "alg": t.Dict[str, JWEAlgModel],
    "enc": t.Dict[str, JWEEncModel],
    "zip": t.Dict[str, JWEZipModel],
})


class JWERegistry:
    """A registry for JSON Web Encryption to keep all the supported algorithms.
    An instance of ``JWERegistry`` is usually used together with methods in
    ``joserfc.jwe``.

    :param header_registry: extra header parameters registry
    :param algorithms: allowed algorithms to be used
    :param verify_all_recipients: validating all recipients in a JSON serialization
    :param strict_check_header: only allow header key in the registry to be used
    """
    algorithms: t.ClassVar[AlgorithmsDict] = {
        "alg": {},
        "enc": {},
        "zip": {},
    }
    recommended: t.ClassVar[t.List[str]] = []

    def __init__(
            self,
            header_registry: t.Optional[HeaderRegistryDict] = None,
            algorithms: list[str] | None = None,
            verify_all_recipients: bool = True,
            strict_check_header: bool = True):
        self.header_registry: HeaderRegistryDict = {}
        self.header_registry.update(JWE_HEADER_REGISTRY)
        if header_registry is not None:
            self.header_registry.update(header_registry)
        self.allowed = algorithms
        self.verify_all_recipients = verify_all_recipients
        self.strict_check_header = strict_check_header

    @classmethod
    def register(cls, model: JWEAlgorithm) -> None:
        cls.algorithms[model.algorithm_location][model.name] = model  # type: ignore
        if model.recommended:
            cls.recommended.append(model.name)

    def check_header(self, header: Header, check_more: bool = False) -> None:
        """Check and validate the fields in header part of a JWS object."""
        check_crit_header(header)
        validate_registry_header(self.header_registry, header)

        alg = self.get_alg(header["alg"])
        if alg.more_header_registry:
            validate_registry_header(alg.more_header_registry, header, check_more)

            if self.strict_check_header:
                allowed_registry = self.header_registry.copy()
                allowed_registry.update(alg.more_header_registry)
                check_supported_header(allowed_registry, header)
        elif self.strict_check_header:
            check_supported_header(self.header_registry, header)

    def get_alg(self, name: str) -> JWEAlgModel:
        """Get the allowed ("alg") algorithm instance of the given name.

        :param name: value of the ``alg``, e.g. ``ECDH-ES``, ``A128KW``
        """
        registry = self.algorithms["alg"]
        self._check_algorithm(name, registry)
        return registry[name]

    def get_enc(self, name: str) -> JWEEncModel:
        """Get the allowed ("enc") algorithm instance of the given name.

        :param name: value of the ``enc``, e.g. ``A128CBC-HS256``, ``A128GCM``
        """
        registry = self.algorithms["enc"]
        self._check_algorithm(name, registry)
        return registry[name]

    def get_zip(self, name: str) -> JWEZipModel:
        """Get the allowed ("zip") algorithm instance of the given name.

        :param name: value of the ``zip``, e.g. ``DEF``
        """
        registry = self.algorithms["zip"]
        self._check_algorithm(name, registry)
        return registry[name]

    def _check_algorithm(self, name: str, registry: dict[str, t.Any]) -> None:
        if name not in registry:
            raise ValueError(f'Algorithm of "{name}" is not supported')

        if self.allowed:
            allowed = self.allowed
        else:
            allowed = self.recommended

        if name not in allowed:
            raise ValueError(f'Algorithm of "{name}" is not allowed')


default_registry = JWERegistry()
