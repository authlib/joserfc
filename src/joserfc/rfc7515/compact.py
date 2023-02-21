import binascii
from .model import JWSAlgModel
from .types import HeaderMember, SignatureData
from ..errors import DecodeError, MissingAlgorithmError
from ..util import (
    to_bytes,
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def sign_compact(obj: SignatureData, alg: JWSAlgModel, key):
    key.check_use('sig')
    member = obj.members[0]
    header_segment = json_b64encode(member.protected)
    if obj.payload_segment is None:
        obj.payload_segment = urlsafe_b64encode(obj.payload)
    signing_input = header_segment + b'.' + obj.payload_segment
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    return signing_input + b'.' + signature


def extract_compact(value: bytes) -> SignatureData:
    """Extract the JWS Compact Serialization from bytes to object.

    :param value: JWS in bytes
    :raise: DecodeError
    """
    parts = value.split(b'.')
    if len(parts) != 3:
        raise ValueError('Invalid JSON Web Signature')

    header_segment, payload_segment, signature = parts
    try:
        protected = json_b64decode(header_segment)
        if 'alg' not in protected:
            raise MissingAlgorithmError()
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid header')

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid payload')

    member = HeaderMember(protected)
    obj = SignatureData([member], payload)
    obj.compact = True
    obj.signatures = [
        {
            'protected': header_segment.decode('utf-8'),
            'signature': signature.decode('utf-8'),
        }
    ]
    obj.payload_segment = payload_segment
    return obj


def verify_compact(obj: SignatureData, alg: JWSAlgModel, key) -> bool:
    key.check_use('sig')
    data = obj.signatures[0]
    header_segment = data['protected']
    signing_input = to_bytes(header_segment) + b'.' + obj.payload_segment
    sig = urlsafe_b64decode(to_bytes(data['signature']))
    return alg.verify(signing_input, sig, key)
