"""Draft consumer fixtures; no issuer, server adapter or real credentials."""
import copy
from dataclasses import replace
import hashlib
import json
import socket
import subprocess
import unittest
from unittest.mock import patch
from handoff_snapshot import prepare
import provisioning_review as consumer
from test_package_client import archive, pack
from test_preflight_client import CONFIG


class Tests(unittest.TestCase):
    def setUp(self):
        package = pack(archive())
        config = json.dumps(CONFIG).encode()
        self.snapshot = prepare(package, config, hashlib.sha256(package).hexdigest(),
                                hashlib.sha256(config).hexdigest())
        # Names are provisional fixture fields, NOT an admitted FAC wire schema.
        self.expectation = {'environment': 'Test', 'issuer': 'fixture-issuer',
                            'audience': 'fixture-client', 'required_scope': 'fixture:prepare',
                            'request_id': 'fixture-request', 'now': 1000}
        self.envelope = {'schema': consumer.DRAFT_SCHEMA, 'environment': 'Test',
                         'issuer': 'fixture-issuer', 'audience': 'fixture-client',
                         'scope': ['fixture:prepare'], 'request_id': 'fixture-request',
                         'credential_id': 'fixture-id', 'credential_version': 1,
                         'credential_kind': 'service_access', 'status': 'active',
                         'issued_at': 900, 'expires_at': 1100,
                         'customer_id': CONFIG['customer_id'], 'agent_id': CONFIG['agent_id'],
                         'infrastructure_id': CONFIG['infrastructure_id'], 'server_id': CONFIG['server_id'],
                         'site_ids': [], 'service_ids': [],
                         'package_sha256': self.snapshot.package_sha256,
                         'config_sha256': self.snapshot.config_sha256,
                         'heartbeat_delivery': 'SEPARATE_CUSTODY_REQUIRED'}

    def review(self, envelope=None):
        blob = envelope if type(envelope) is bytes else json.dumps(self.envelope if envelope is None else envelope).encode()
        with patch('socket.socket', side_effect=AssertionError('network forbidden')) as network, \
                patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')) as process:
            try:
                return consumer.review(self.snapshot, blob, self.expectation)
            finally:
                network.assert_not_called()
                process.assert_not_called()

    def test_matching_draft_is_never_authority(self):
        result = self.review()
        self.assertEqual(result['review'], 'COMPATIBLE_DRAFT_NOT_AUTHENTICATED')
        self.assertEqual(result['integration'], 'HELD')
        self.assertEqual(result['installation'], 'HELD')
        self.assertEqual(result['activation'], 'HELD')

    def test_cross_environment_tenant_target_audience_and_request_rejected(self):
        for key in ('environment', 'issuer', 'audience', 'request_id', 'customer_id',
                    'agent_id', 'infrastructure_id', 'server_id', 'package_sha256', 'config_sha256'):
            value = dict(self.envelope, **{key: 'other'})
            with self.subTest(field=key), self.assertRaises(consumer.ProvisioningRejected):
                self.review(value)

    def test_scope_and_key_kind_do_not_grant_other_capabilities(self):
        for key, value in (('scope', ['felix_watch:read']), ('scope', ['felix_watch:heartbeat']),
                           ('credential_kind', 'heartbeat_hmac'), ('heartbeat_delivery', 'reuse_api_key')):
            with self.subTest(field=key), self.assertRaises(consumer.ProvisioningRejected):
                self.review(dict(self.envelope, **{key: value}))

    def test_expiry_revocation_and_clock_boundaries_fail_closed(self):
        for key, value in (('expires_at', 1000), ('expires_at', 899), ('issued_at', 1001),
                           ('status', 'revoked'), ('status', 'rotated'), ('credential_version', 0),
                           ('expires_at', True), ('expires_at', 2**64)):
            with self.subTest(field=key), self.assertRaises(consumer.ProvisioningRejected):
                self.review(dict(self.envelope, **{key: value}))

    def test_missing_unknown_plaintext_and_control_fields_rejected(self):
        for field in self.envelope:
            value = dict(self.envelope)
            del value[field]
            with self.subTest(missing=field), self.assertRaises(consumer.ProvisioningRejected):
                self.review(value)
        for field in ('api_key', 'hmac_secret', 'token', 'endpoint', 'admitted'):
            with self.assertRaises(consumer.ProvisioningRejected) as error:
                self.review(dict(self.envelope, **{field: 'synthetic-secret-canary'}))
            self.assertNotIn('synthetic-secret-canary', str(error.exception))
        with self.assertRaises(consumer.ProvisioningRejected):
            self.review(dict(self.envelope, credential_id='bad\nvalue'))

    def test_site_service_scope_and_duplicate_lists_rejected(self):
        for field, value in (('site_ids', ['other']), ('service_ids', ['other']),
                             ('scope', ['fixture:prepare', 'fixture:prepare'])):
            with self.assertRaises(consumer.ProvisioningRejected):
                self.review(dict(self.envelope, **{field: value}))

    def test_tampered_snapshot_is_revalidated(self):
        self.snapshot = replace(self.snapshot, config=b'{}')
        with self.assertRaises(consumer.ProvisioningRejected):
            self.review()

    def test_json_bounds_duplicates_and_malformed_input_are_sanitized(self):
        for blob in (b'x'*16385, b'{"token":"synthetic-secret-canary",',
                     b'{"schema":1,"schema":2}'):
            with self.assertRaises(consumer.ProvisioningRejected) as error:
                self.review(blob)
            self.assertNotIn('synthetic-secret-canary', str(error.exception))

    def test_caller_data_is_preserved(self):
        before = copy.deepcopy((self.envelope, self.expectation))
        self.review()
        self.assertEqual(before, (self.envelope, self.expectation))

    def test_fault_injection_cannot_hide_forbidden_network_attempt(self):
        for attempt in (lambda snapshot: socket.socket(), lambda snapshot: subprocess.Popen(['synthetic'])):
            with patch.object(consumer, 'verify_for_review', side_effect=attempt), \
                    self.assertRaises(AssertionError):
                self.review()


if __name__ == '__main__':
    unittest.main()
