import json
from typing import Dict, Any
from pathlib import Path

TESTS_PATH = Path(__file__).parent


def read_key(filename: str, mode: str="rb") -> bytes:
    with open((TESTS_PATH / "keys" / filename).resolve(), mode) as f:
        return f.read()


def read_fixture(filename: str) -> Dict[str, Any]:
    with open((TESTS_PATH / "fixtures" / filename).resolve()) as f:
        return json.load(f)
