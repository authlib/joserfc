from typing import Dict
from .models import JWEAlgModel, JWEEncModel, JWEZipModel

#: registry to store all the models for "alg"
JWE_ALG_REGISTRY: Dict[str, JWEAlgModel] = {}

#: registry to store all the models for "enc"
JWE_ENC_REGISTRY: Dict[str, JWEEncModel] = {}

#: registry to store all the models for "zip"
JWE_ZIP_REGISTRY: Dict[str, JWEZipModel] = {}
