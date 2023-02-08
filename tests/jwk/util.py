from pathlib import Path

KEYS_PATH = Path(__file__).parent.parent / "keys"


def read_key(filename, mode="rb"):
    with open((KEYS_PATH / filename).resolve(), mode) as f:
        return f.read()

