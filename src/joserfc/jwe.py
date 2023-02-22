from typing import Optional, List, AnyStr, TypedDict
from .rfc7516.types import Header, EncryptionData, Recipient
from .rfc7516.header import check_header
from .rfc7516.registry import (
    register_alg_model,
    register_enc_model,
    register_zip_model,
    get_alg_model,
    get_enc_model,
    get_zip_model,
)
from .rfc7516.compact import (
    extract_compact,
    encrypt_compact as _encrypt_compact,
    decrypt_compact as _decrypt_compact,
)
from .rfc7518.jwe_algs import JWE_ALG_MODELS
from .rfc7518.jwe_encs import JWE_ENC_MODELS
from .rfc7518.jwe_zips import JWE_ZIP_MODELS
from .jwk import KeyFlexible, guess_key
from .util import to_bytes

AllowedAlgorithms = TypedDict('AllowedAlgorithms', {
    'alg': List[str],
    'enc': List[str],
    'zip': List[str],
}, total=False)


__all__ = [
    'encrypt_compact',
    'decrypt_compact',
    'extract_compact',
]

def __register():
    for _alg in JWE_ALG_MODELS:
        register_alg_model(_alg)

    for _enc in JWE_ENC_MODELS:
        register_enc_model(_enc)

    for _zip in JWE_ZIP_MODELS:
        register_zip_model(_zip)

__register()


def encrypt_compact(
        protected: Header,
        payload: bytes,
        public_key: KeyFlexible,
        sender_key=None,
        allowed_algorithms: Optional[AllowedAlgorithms]=None) -> bytes:

    check_header(protected, ['alg', 'enc'])
    alg, enc, zip_ = _get_algorithms(protected, allowed_algorithms)
    recipient = Recipient(protected)
    wrap_key = guess_key(public_key, recipient, 'wrapKey')
    obj = EncryptionData(recipient.header, payload)
    obj.compact = True
    return _encrypt_compact(obj, wrap_key, alg, enc, zip_, sender_key)


def decrypt_compact(
        value: AnyStr,
        private_key: KeyFlexible,
        sender_key=None,
        allowed_algorithms: Optional[AllowedAlgorithms] = None) -> EncryptionData:
    value = to_bytes(value)
    obj = extract_compact(value)
    check_header(obj.protected, ['alg', 'enc'])
    alg, enc, zip_ = _get_algorithms(obj.protected, allowed_algorithms)
    unwrap_key = guess_key(private_key, obj.recipients[0], 'unwrapKey')
    return _decrypt_compact(obj, unwrap_key, alg, enc, zip_, sender_key)


def _get_algorithms(protected: Header, allowed_algorithms: Optional[AllowedAlgorithms]):
    alg = get_alg_model(protected['alg'], _get_allowed_algorithms('alg', allowed_algorithms))
    enc = get_enc_model(protected['enc'], _get_allowed_algorithms('enc', allowed_algorithms))
    if 'zip' in protected:
        zip_ = get_zip_model(protected['zip'], _get_allowed_algorithms('zip', allowed_algorithms))
    else:
        zip_ = None
    return alg, enc, zip_

def _get_allowed_algorithms(key: str, allowed_algorithms: Optional[AllowedAlgorithms]):
    if allowed_algorithms and key in allowed_algorithms:
        return allowed_algorithms[key]
    else:
        return None
