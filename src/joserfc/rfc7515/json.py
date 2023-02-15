import typing as t
from .alg import JWSAlgorithm
from .types import Header, Signature, HeaderMember, JSONSerialization
from ..util import (
    json_b64encode,
    json_b64decode,
    urlsafe_b64encode,
    urlsafe_b64decode,
)

FindAlgorithm = t.Callable[[HeaderMember], JWSAlgorithm]


class JSONData:
    def __init__(self, members: t.List[HeaderMember], payload: bytes, flatten: bool=False):
        self.members = []
        self.payload = payload
        self.flatten = flatten
        self.signatures: t.List[Signature] = []
        self._payload_segment = None

    @property
    def payload_segment(self) -> bytes:
        if not self._payload_segment:
            self._payload_segment = urlsafe_b64encode(self.payload)
        return self._payload_segment

    def sign(self, find_alg: FindAlgorithm, find_key) -> JSONSerialization:
        self.signatures: t.List[Signature] = []
        for member in self.members:
            alg = find_alg(member)
            key = find_key(member)
            signature = self._sign_member(member, alg, key)
            self.signatures.append(signature)

        rv = {'payload': self.payload_segment.decode('utf-8')}
        if self.flatten and len(self.signatures) == 1:
            rv.update(self.signatures[0])
        else:
            rv['signatures'] = self.signatures
        return rv

    def verify(self, find_alg: FindAlgorithm, find_key) -> bool:
        """Verify the signature of this JSON serialization with the given
        algorithm and key.

        :param algorithm: a registered algorithm instance
        :param find_key: a function to return public key
        """
        for index, signature in enumerate(self.signatures):
            alg = find_alg(self.members[index])
            key = find_key(self.members[index])
            if not self._verify_signature(signature, alg, key):
                return False
        return True

    def _sign_member(self, member: HeaderMember, algorithm: JWSAlgorithm, key) -> Signature:
        protected_segment = json_b64encode(member['protected'])
        signing_input = b'.'.join([protected_segment, self.payload_segment])
        signature = urlsafe_b64encode(algorithm.sign(signing_input, key))
        rv = {
            'protected': protected_segment.decode('utf-8'),
            'signature': signature.decode('utf-8'),
        }
        if 'header' in member and isinstance(member['header'], dict):
            rv['header'] = member['header']
        return rv

    def _verify_signature(self, signature: Signature, algorithm: JWSAlgorithm, key) -> bool:

        protected_segment = signature['protected'].encode('utf-8')
        sig = urlsafe_b64decode(signature['signature'].encode('utf-8'))
        signing_input = b'.'.join([protected_segment, self.payload_segment])
        return algorithm.verify(signing_input, sig, key)


def extract_json(value: JSONSerialization) -> JSONData:
    """Extract the JWS JSON Serialization from dict to object.

    :param value: JWS in dict
    """
    payload_segment = value['payload']

    try:
        payload = urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError, binascii.Error):
        raise DecodeError('Invalid payload')

    if 'signatures' in value:
        flatten = False
        signatures = value['signatures']
    else:
        flatten = True
        _sig = {
            'protected': value['protected'],
            'signature': value['signature'],
        }
        if 'header' in value:
            _sig['header'] = value['header']
        signatures = [_sig]

    members = []
    for sig in signatures:
        protected_segment = sig['protected']
        _member = {
            'protected': json_b64decode(protected_segment),
        }
        if 'header' in sig:
            _member['header'] = sig['header']
        members.append(_member)

    obj = JSONData(members, payload, flatten)
    obj.signatures = signatures
    obj._payload_segment = payload_segment
    return obj
