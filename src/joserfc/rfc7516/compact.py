from typing import Optional
from .models import JWEAlgModel, JWEEncModel, JWEZipModel
from .types import Header


class CompactData:
    def __init__(self, header: Header, payload: bytes):
        self.header = header
        self.payload = payload

    def sign(
            self,
            alg: JWEAlgModel,
            enc: JWEEncModel,
            zip_alg: Optional[JWEZipModel],
            public_key,
            sender_key=None):
        pass
