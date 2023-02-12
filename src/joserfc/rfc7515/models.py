from typing import Required, List, TypedDict, Any


ProtectedHeader = TypedDict('ProtectedHeader', {
    'alg': Required[str],
    'jku': str,
    'jwk': str,
    'kid': str,
    'x5u': str,
    'x5c': str,
    'x5t': str,
    'x5t#S256': str,
    'typ': str,
    'cty': str,
    'crit': List[str],
}, total=False)



class CompactData:
    def __init__(self, header: Dict[str, Any], payload, signature=None):
        self.header = header
        self.payload = payload
        self.signature = signature

    @property
    def protected_header(self) -> ProtectedHeader:
        return



class JsonData:
    def __init__(self, headers, payload, signatures=None):
        if isinstance(headers, dict):
            self.flat = True
        else:
            self.flat = False
        self.headers = headers
        self.payload = payload
        self.signatures = signatures
