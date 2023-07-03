import json
from pathlib import Path

BASE_PATH = Path(__file__).parent


def read_key(filename: str):
    with open((BASE_PATH / filename).resolve(), "rb") as f:
        content: bytes = f.read()

    if filename.endswith(".json"):
        return json.loads(content)
    return content
