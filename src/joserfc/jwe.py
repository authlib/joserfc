from typing import Optional, List
from .rfc7516.types import Header
from .rfc7516.header import check_header
from .rfc7516.registry import JWE_ALG_REGISTRY, JWE_ENC_REGISTRY, JWE_ZIP_REGISTRY
from .rfc7518.jwe_encs import JWE_ENC_MODELS
from .rfc7518.jwe_zips import JWE_ZIP_MODELS
from .jwk import KeyFlexible


__all__ = [
    'JWE_ALG_REGISTRY',
    'JWE_ENC_REGISTRY',
    'JWE_ZIP_REGISTRY',
    'serialize_compact',
]

def __register():
    for _enc in JWE_ENC_MODELS:
        JWE_ENC_MODELS[_enc.name] = _enc

    for _zip in JWE_ZIP_MODELS:
        JWE_ZIP_REGISTRY[_zip.name] = _zip
__register()


def serialize_compact(
        header: Header,
        payload: bytes,
        public_key: KeyFlexible,
        sender_key=None,
        allowed_algorithms: Optional[List[str]]=None) -> bytes:
    check_header(header, ['alg', 'enc'])
