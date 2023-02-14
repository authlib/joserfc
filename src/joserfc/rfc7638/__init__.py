import hashlib
from collections import OrderedDict
from ..rfc7517 import Key
from .._util import to_bytes, json_dumps, urlsafe_b64encode


def thumbprint(key: Key) -> str:
    fields = list(key.required_fields)
    fields.sort()

    data = OrderedDict()
    for k in fields:
        data[k] = key.tokens[k]

    json_data = json_dumps(data)
    digest_data = hashlib.sha256(to_bytes(json_data)).digest()
    kid = urlsafe_b64encode(digest_data).decode('utf-8')
    key.kid = kid
    return kid
