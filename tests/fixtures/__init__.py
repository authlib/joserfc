import json
from unittest import TestCase
from ..util import read_fixture


class TestFixture(TestCase):
    @classmethod
    def load_fixture(cls, filename: str, private_key, public_key):
        data = read_fixture(filename)

        payload = data.get('payload')
        root_id = data.get('id', '')
        for index, case in enumerate(data['cases']):
            if 'id' not in case:
                alg = case.get('alg', '')
                case['id'] = f'{root_id}_{alg}_{index}'

            if payload and 'payload' not in case:
                case['payload'] = payload
            cls.attach_case(case, private_key, public_key)

    @classmethod
    def attach_case(cls, case, private_key, public_key):

        def method(self):
            self.run_test(case, private_key, public_key)

        case_id = case['id']
        name = f'test_{case_id}'
        method.__name__ = name
        method.__doc__ = f'Run fixture {case}'
        setattr(cls, name, method)

    def run_test(self, case, private_key, public_key):
        raise NotImplementedError()
