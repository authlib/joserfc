import json
import typing as t
from joserfc.jwk import import_key
from unittest import TestCase
from pathlib import Path

BASE_PATH = Path(__file__).parent


def read_fixture(filename: str):
    with open((BASE_PATH / "fixtures" / filename).resolve()) as f:
        return json.load(f)


def load_key(filename: str, parameters=None):
    with open((BASE_PATH / "keys" / filename).resolve(), "rb") as f:
        content: bytes = f.read()

    if filename.endswith(".json"):
        data = json.loads(content)
        return import_key(data, parameters=parameters)

    kty = filename.split("-", 1)[0]
    return import_key(content, kty.upper(), parameters)


class TestFixture(TestCase):
    @classmethod
    def load_fixture(cls, filename: str):
        fixture_data = read_fixture(filename)

        for case_data in fixture_data["tests"]:
            if "payload" not in case_data and "payload" in fixture_data:
                case_data["payload"] = fixture_data["payload"]
            cls.attach_case(case_data)

    @classmethod
    def attach_case(cls, data):
        runner = data.get("runner", "run_test")

        def method(self):
            getattr(self, runner)(data)

        case_name = data["name"]
        name = f"test_{case_name}"
        method.__name__ = name
        method.__doc__ = f"Run fixture {data}"
        setattr(cls, name, method)

    def run_test(self, data: t.Dict[str, t.Any]):
        raise NotImplementedError()
