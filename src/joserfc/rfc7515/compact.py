import binascii
from .model import JWSAlgModel
from .types import HeaderMember, SignatureData
from ..errors import DecodeError, MissingAlgorithmError
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)


def sign_compact(obj: SignatureData, alg: JWSAlgModel, key) -> bytes:
    key.check_use('sig')
    member = obj.members[0]
    if 'header' not in obj.segments:
        obj.segments['header'] = json_b64encode(member.protected)
    if 'payload' not in obj.segments:
        obj.segments['payload'] = urlsafe_b64encode(obj.payload)
    signing_input = obj.segments['header'] + b'.' +  obj.segments['payload']
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    obj.segments['signature'] = signature
    return signing_input + b'.' + signature


def extract_compact(value: bytes) -> SignatureData:
    """Extract the JWS Compact Serialization from bytes to object.

    :param value: JWS in bytes
    :raise: DecodeError
    """
    parts = value.split(b'.')
    if len(parts) != 3:
        raise ValueError('Invalid JSON Web Signature')

    header_segment, payload_segment, signature_segment = parts
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

    obj = SignatureData([HeaderMember(protected)], payload)
    obj.compact = True
    obj.segments.update({
        'header': header_segment,
        'payload': payload_segment,
        'signature': signature_segment,
    })
    return obj


def verify_compact(obj: SignatureData, alg: JWSAlgModel, key) -> bool:
    key.check_use('sig')
    signing_input = obj.segments['header'] + b'.' + obj.segments['payload']
    sig = urlsafe_b64decode(obj.segments['signature'])
    return alg.verify(signing_input, sig, key)
