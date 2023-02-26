import typing as t
import hashlib
from collections import OrderedDict
from ..util import to_bytes, json_dumps, urlsafe_b64encode


def thumbprint(dict_value: t.Dict[str, str], fields: t.List[str]) -> str:
    fields.sort()

    data = OrderedDict()
    for k in fields:
        data[k] = dict_value[k]

    json_data = json_dumps(data)
    digest_data = hashlib.sha256(to_bytes(json_data)).digest()
    return urlsafe_b64encode(digest_data).decode('utf-8')
