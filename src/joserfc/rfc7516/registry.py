from typing import Dict, Optional, List
from .models import JWEAlgModel, JWEEncModel, JWEZipModel

#: registry to store all the models for "alg"
JWE_ALG_REGISTRY: Dict[str, JWEAlgModel] = {}

#: registry to store all the models for "enc"
JWE_ENC_REGISTRY: Dict[str, JWEEncModel] = {}

#: registry to store all the models for "zip"
JWE_ZIP_REGISTRY: Dict[str, JWEZipModel] = {}

#: recommended alg models
RECOMMENDED_ALG_MODELS: List[str] = []

#: recommended enc models
RECOMMENDED_ENC_MODELS: List[str] = []

#: recommended zip models
RECOMMENDED_ZIP_MODELS: List[str] = []


def register_alg_model(model: JWEAlgModel):
    JWE_ALG_REGISTRY[model.name] = model


def get_alg_model(name: str, allowed: Optional[List[str]]=None) -> JWEAlgModel:
    if allowed is None:
        allowed = RECOMMENDED_ALG_MODELS
    return _get_model(name, JWE_ALG_REGISTRY, allowed)


def register_enc_model(model: JWEEncModel):
    JWE_ENC_REGISTRY[model.name] = model


def get_enc_model(name: str, allowed: Optional[List[str]]=None) -> JWEEncModel:
    if allowed is None:
        allowed = RECOMMENDED_ENC_MODELS
    return _get_model(name, JWE_ENC_REGISTRY, allowed)

def register_zip_model(model: JWEZipModel):
    JWE_ZIP_REGISTRY[model.name] = model


def get_zip_model(name: str, allowed: Optional[List[str]]=None) -> JWEAlgModel:
    if allowed is None:
        allowed = RECOMMENDED_ZIP_MODELS
    return _get_model(name, JWE_ZIP_REGISTRY, allowed)


def _get_model(name: str, registry, allowed):
    if name not in registry:
        raise ValueError(f'Model of "{name}" is not supported')
    if name not in allowed:
        raise ValueError(f'Model of "{name}" is not allowed')
    return registry[name]
