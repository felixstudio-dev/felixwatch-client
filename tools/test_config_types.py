import copy
import json
import unittest
from preflight_client import validate_config
from test_preflight_client import CONFIG


class ConfigTypeTests(unittest.TestCase):
    def check_rejected(self, field, value):
        cfg = copy.deepcopy(CONFIG)
        cfg.update(field)
        with self.assertRaises(ValueError):
            validate_config(json.dumps(cfg).encode())

    def test_integer_fields_reject_nonintegers_and_overflow(self):
        for key in ('interval_seconds', 'queue_max_bytes'):
            for value in (True, False, '1', 1.0, None, [], {}, 2**63, -(2**63)-1):
                with self.subTest(key=key, value=value):
                    self.check_rejected({key: value}, value)

    def test_nested_integer_types(self):
        for key in ('expected_status', 'timeout_seconds'):
            for value in (True, '200', 200.0, None, [], {}, 2**63):
                with self.subTest(key=key, value=value):
                    self.check_rejected({'sites': [{'url': 'https://example.com', key: value}]}, value)

    def test_service_scalar_types(self):
        for key in ('service_id', 'pid_file', 'expected_comm'):
            for value in (False, 1, None, [], {}):
                with self.subTest(key=key, value=value):
                    self.check_rejected({'services': [{key: value}]}, value)
        for value in (0, 1, 'true', None, [], {}):
            self.check_rejected({'services': [{'essential': value}]}, value)

    def test_remaining_string_fields(self):
        for key in ('collector_url', 'queue_path', 'secret_env'):
            for value in (False, 1, None, [], {}):
                with self.subTest(key=key, value=value):
                    self.check_rejected({key: value}, value)

    def test_valid_optional_fields_and_boundaries(self):
        cfg = copy.deepcopy(CONFIG)
        cfg.update(interval_seconds=60, queue_max_bytes=2**63-1, queue_path='/tmp/q')
        cfg['sites'] = [{'site_id': 's1', 'url': 'https://example.com', 'expected_status': 200, 'timeout_seconds': 5}]
        cfg['services'] = [{'service_id': 'svc', 'pid_file': '/run/svc.pid', 'expected_comm': 'svc', 'essential': False}]
        self.assertEqual(validate_config(json.dumps(cfg).encode()), cfg)


if __name__ == '__main__':
    unittest.main()
