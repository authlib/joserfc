import typing as t
import binascii
from .model import JWSAlgModel
from .types import (
    HeaderMember,
    SignatureData,
    JSONSignatureDict,
    JSONSerialization,
    CompleteJSONSerialization,
    FlattenJSONSerialization,
)
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)
from ..errors import DecodeError

FindAlgorithm = t.Callable[[str], JWSAlgModel]


def sign_json(obj: SignatureData, find_alg: FindAlgorithm, find_key) -> JSONSerialization:
    signatures: t.List[JSONSignatureDict] = []

    payload_segment = obj.segments['payload']
    for member in obj.members:
        alg = find_alg(member.protected['alg'])
        key = find_key(member)
        key.check_use('sig')
        signature = _sign_member(payload_segment, member, alg, key)
        signatures.append(signature)

    rv = {'payload': payload_segment.decode('utf-8')}
    if obj.flatten and len(signatures) == 1:
        rv.update(dict(signatures[0]))
    else:
        rv['signatures'] = signatures

    obj.signatures = signatures
    return rv


def _sign_member(payload_segment, member: HeaderMember, alg: JWSAlgModel, key) -> JSONSignatureDict:
    protected_segment = json_b64encode(member.protected)
    signing_input = b'.'.join([protected_segment, payload_segment])
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    rv = {
        'protected': protected_segment.decode('utf-8'),
        'signature': signature.decode('utf-8'),
    }
    if member.header:
        rv['header'] = member.header
    return rv


def extract_json(value: JSONSerialization) -> SignatureData:
    """Extract the JWS JSON Serialization from dict to object.

    :param value: JWS in dict
    """
    payload_segment: bytes = value['payload'].encode('utf-8')

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid payload')

    if 'signatures' in value:
        flatten = False
        value: CompleteJSONSerialization
        signatures: t.List[JSONSignatureDict] = value['signatures']
    else:
        flatten = True
        value: FlattenJSONSerialization
        _sig: JSONSignatureDict = {
            'protected': value['protected'],
            'signature': value['signature'],
        }
        if 'header' in value:
            _sig['header'] = value['header']
        signatures = [_sig]

    members = []
    for sig in signatures:
        protected_segment = sig['protected']
        protected = json_b64decode(protected_segment)
        member = HeaderMember(protected)
        if 'header' in sig:
            member.header = sig['header']
        members.append(member)

    obj = SignatureData(members, payload)
    obj.segments.update({'payload': payload_segment})
    obj.flatten = flatten
    obj.signatures = signatures
    return obj


def verify_json(obj: SignatureData, find_alg: FindAlgorithm, find_key) -> bool:
    """Verify the signature of this JSON serialization with the given
    algorithm and key.

    :param obj: instance of the SignatureData
    :param find_alg: a function to return "alg" model
    :param find_key: a function to return public key
    """
    payload_segment = obj.segments['payload']
    for index, signature in enumerate(obj.signatures):
        member = obj.members[index]
        alg = find_alg(member.protected['alg'])
        key = find_key(member)
        key.check_use('sig')
        if not _verify_signature(signature, payload_segment, alg, key):
            return False
    return True


def _verify_signature(signature: JSONSignatureDict, payload_segment, alg: JWSAlgModel, key) -> bool:
    protected_segment = signature['protected'].encode('utf-8')
    sig = urlsafe_b64decode(signature['signature'].encode('utf-8'))
    signing_input = b'.'.join([protected_segment, payload_segment])
    return alg.verify(signing_input, sig, key)
