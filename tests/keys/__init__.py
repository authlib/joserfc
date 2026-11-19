import json
from pathlib import Path

BASE_PATH = Path(__file__).parent


def read_key(filename: str):
    with open((BASE_PATH / filename).resolve(), "rb") as f:
        content: bytes = f.read()

    if filename.endswith(".json"):
        return json.loads(content)

    # as_pem() emits LF line endings on every platform. A checkout with Git's
    # autocrlf enabled can give the PEM fixtures CRLF endings on Windows, which
    # makes byte-for-byte comparisons in the tests fail for no good reason.
    return content.replace(b"\r\n", b"\n")
