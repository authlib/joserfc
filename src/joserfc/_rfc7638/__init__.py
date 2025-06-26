import typing as t
import json
import hashlib
from collections import OrderedDict
from ..util import to_bytes, urlsafe_b64encode


def thumbprint(
    dict_value: t.Dict[str, t.Any],
    fields: t.List[str],
    digest_method: t.Literal["sha256", "sha384", "sha512"] = "sha256",
) -> str:
    sorted_fields = sorted(fields)

    data = OrderedDict()
    for k in sorted_fields:
        data[k] = dict_value[k]

    json_data = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    hash_value = hashlib.new(digest_method, to_bytes(json_data))
    digest_data = hash_value.digest()
    return urlsafe_b64encode(digest_data).decode("utf-8")
