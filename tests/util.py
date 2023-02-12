import json
from pathlib import Path

TESTS_PATH = Path(__file__).parent


def read_key(filename, mode="rb"):
    with open((TESTS_PATH / "keys" / filename).resolve(), mode) as f:
        return f.read()


def read_fixture(filename):
    with open((TESTS_PATH / "fixtures" / filename).resolve()) as f:
        return json.load(f)
