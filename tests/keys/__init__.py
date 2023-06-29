import json
from pathlib import Path
from joserfc.jwk import JWKRegistry

BASE_PATH = Path(__file__).parent


def load_key(filename: str, options=None):
    with open((BASE_PATH / filename).resolve(), "rb") as f:
        content: bytes = f.read()

    if filename.endswith(".json"):
        data = json.loads(content)
        return JWKRegistry.import_key(data, options=options)

    kty = filename.split('-', 1)[0]
    return JWKRegistry.import_key(content, kty.upper(), options)


def read_key(filename: str):
    with open((BASE_PATH / filename).resolve(), "rb") as f:
        content: bytes = f.read()

    if filename.endswith(".json"):
        return json.loads(content)
    return content
