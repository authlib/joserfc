from typing import Type, Dict
from .keys import Key

#: registry to store all registered keys
JWK_REGISTRY: Dict[str, Type[Key]] = {}
