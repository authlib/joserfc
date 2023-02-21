from typing import Dict, Optional, List
from .models import JWEAlgModel, JWEEncModel, JWEZipModel

#: registry to store all the models for "alg"
JWE_ALG_REGISTRY: Dict[str, JWEAlgModel] = {}

#: registry to store all the models for "enc"
JWE_ENC_REGISTRY: Dict[str, JWEEncModel] = {}

#: registry to store all the models for "zip"
JWE_ZIP_REGISTRY: Dict[str, JWEZipModel] = {}

#: recommended alg models
RECOMMENDED_ALG_NAMES: List[str] = []

#: recommended enc models
RECOMMENDED_ENC_NAMES: List[str] = []

#: recommended zip models
RECOMMENDED_ZIP_NAMES: List[str] = []


def register_alg_model(model: JWEAlgModel):
    _register_model(model, JWE_ALG_REGISTRY, RECOMMENDED_ALG_NAMES)


def get_alg_model(name: str, allowed: Optional[List[str]]=None) -> JWEAlgModel:
    return _get_model(name, JWE_ALG_REGISTRY, allowed, RECOMMENDED_ALG_NAMES)


def register_enc_model(model: JWEEncModel):
    _register_model(model, JWE_ENC_REGISTRY, RECOMMENDED_ENC_NAMES)


def get_enc_model(name: str, allowed: Optional[List[str]]=None) -> JWEEncModel:
    return _get_model(name, JWE_ENC_REGISTRY, allowed, RECOMMENDED_ENC_NAMES)


def register_zip_model(model: JWEZipModel):
    _register_model(model, JWE_ZIP_REGISTRY, RECOMMENDED_ZIP_NAMES)


def get_zip_model(name: str, allowed: Optional[List[str]]=None) -> JWEAlgModel:
    return _get_model(name, JWE_ZIP_REGISTRY, allowed, RECOMMENDED_ZIP_NAMES)


def _get_model(name: str, registry, allowed, recommended):
    if name not in registry:
        raise ValueError(f'Model of "{name}" is not supported')
    if allowed is None:
        allowed = recommended
    if name not in allowed:
        raise ValueError(f'Model of "{name}" is not allowed')
    return registry[name]


def _register_model(model, registry, recommended):
    registry[model.name] = model
    if model.recommended:
        recommended.append(model.name)
