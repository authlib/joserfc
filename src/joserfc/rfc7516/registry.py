from typing import Type, Dict
from .algs import JWEAlgModel, JWEEncModel, JWEZipModel

#: registry to store all the models for "alg"
JWE_ALG_REGISTRY: Dict[str, Type[JWEAlgModel]] = {}

#: registry to store all the models for "enc"
JWE_ENC_REGISTRY: Dict[str, Type[JWEEncModel]] = {}

#: registry to store all the models for "zip"
JWE_ZIP_REGISTRY: Dict[str, Type[JWEZipModel]] = {}
