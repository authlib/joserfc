from typing import Optional, List
from .rfc7516.types import Header
from .rfc7516.header import check_header
from .rfc7516.registry import JWE_ALG_REGISTRY, JWE_ENC_REGISTRY, JWE_ZIP_REGISTRY
from .jwk import KeyFlexible


__all__ = [
    'JWE_ALG_REGISTRY',
    'JWE_ENC_REGISTRY',
    'JWE_ZIP_REGISTRY',
    'serialize_compact',
]


def serialize_compact(
        header: Header,
        payload: bytes,
        public_key: KeyFlexible,
        sender_key=None,
        allowed_algorithms: Optional[List[str]]=None) -> bytes:
    check_header(header, ['alg', 'enc'])
