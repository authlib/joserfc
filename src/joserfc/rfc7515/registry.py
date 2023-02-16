from typing import Dict, List, Optional
from .model import JWSAlgModel

#: registry to store all the models for "alg"
JWS_ALG_REGISTRY: Dict[str, JWSAlgModel] = {}

#: recommended alg models
RECOMMENDED_ALG_MODELS: List[str] = []


def register_alg_model(alg: JWSAlgModel):
    JWS_ALG_REGISTRY[alg.name] = alg


def get_alg_model(alg: str, allowed: Optional[List[str]]=None) -> JWSAlgModel:
    if alg not in JWS_ALG_REGISTRY:
        raise ValueError(f'Model of "{alg}" is not supported')
    if allowed is None:
        allowed = RECOMMENDED_ALG_MODELS
    if alg not in allowed:
        raise ValueError(f'Model of "{alg}" is not allowed')
    return JWS_ALG_REGISTRY[alg]
