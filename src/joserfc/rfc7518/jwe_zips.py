import zlib
from typing import List
from ..rfc7516.models import JWEZipModel


class DeflateZipModel(JWEZipModel):
    name = "DEF"
    description = "DEFLATE"

    def compress(self, s: bytes) -> bytes:
        """Compress bytes data with DEFLATE algorithm."""
        data = zlib.compress(s)
        # drop gzip headers and tail
        return data[2:-4]

    def decompress(self, s: bytes) -> bytes:
        """Decompress DEFLATE bytes data."""
        return zlib.decompress(s, -zlib.MAX_WBITS)


JWE_ZIP_MODELS: List[JWEZipModel] = [DeflateZipModel()]
