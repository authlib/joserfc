from __future__ import annotations
import zlib
from ..rfc7516.models import JWEZipModel
from ..errors import ExceededSizeError

GZIP_HEAD = bytes([120, 156])
MAX_SIZE = 250 * 1024


class DeflateZipModel(JWEZipModel):
    name = "DEF"
    description = "DEFLATE"

    def compress(self, s: bytes) -> bytes:
        """Compress bytes data with DEFLATE algorithm."""
        data = zlib.compress(s)
        # https://datatracker.ietf.org/doc/html/rfc1951
        # since DEF is always gzip, we can drop gzip headers and tail
        return data[2:-4]

    def decompress(self, s: bytes) -> bytes:
        """Decompress DEFLATE bytes data."""
        if s.startswith(GZIP_HEAD):
            decompressor = zlib.decompressobj()
        else:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
        value = decompressor.decompress(s, MAX_SIZE)
        if decompressor.unconsumed_tail:
            raise ExceededSizeError(f"Decompressed string exceeds {MAX_SIZE} bytes")
        return value


JWE_ZIP_MODELS: list[JWEZipModel] = [DeflateZipModel()]
