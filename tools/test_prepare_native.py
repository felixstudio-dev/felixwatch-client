"""Synthetic offline user-flow tests; no installation or provisioning."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_native as native
from test_package_client import archive, pack
from test_preflight_client import CONFIG


CANARY = b'synthetic-input-canary.not-a-credential'


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / 'candidate.tar.gz'
        self.config = self.root / 'agent.json'
        self.queue = self.root / 'existing.queue'
        self.package.write_bytes(pack(archive()))
        self.config.write_text(json.dumps(CONFIG), encoding='utf-8')
        self.queue.write_bytes(b'preserve existing queue')
        # Fixture history only. Never inspect or alter the operator's real history.
        (self.root / '.synthetic_history').write_text('prepare-native --help\n', encoding='utf-8')
        self.args = ['--package', str(self.package), '--package-sha256',
                     hashlib.sha256(self.package.read_bytes()).hexdigest(),
                     '--config', str(self.config), '--config-sha256',
                     hashlib.sha256(self.config.read_bytes()).hexdigest()]

    def run_flow(self, args=None):
        output = io.StringIO()
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output), \
                patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                patch('subprocess.Popen', side_effect=AssertionError('process forbidden')):
            code = native.main(self.args if args is None else args)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertNotIn(CANARY.decode(), output.getvalue())
        return code, json.loads(output.getvalue())

    def test_offline_preparation_remains_held_without_prompt(self):
        with patch.object(native, 'read_protected_key', side_effect=AssertionError('unexpected prompt')):
            code, receipt = self.run_flow()
        self.assertEqual(code, 3)
        self.assertEqual(receipt['preparation'], 'PASS')
        self.assertEqual(receipt['key_input'], 'NOT_REQUESTED')
        self.assertEqual(receipt['provisioning'], 'HELD')
        self.assertEqual(receipt['installation'], 'HELD')

    def test_prompt_input_is_discarded_not_hmac_or_authority(self):
        secret = bytearray(CANARY)
        with patch.object(native, 'read_protected_key', return_value=secret):
            code, receipt = self.run_flow(self.args + ['--check-key-input'])
        self.assertEqual(code, 3)
        self.assertEqual(receipt['key_input'], 'FORMAT_ONLY_NOT_AUTHENTICATED')
        self.assertEqual(secret, bytearray(len(CANARY)))
        self.assertNotIn(CANARY.decode(), ' '.join(self.args))

    def test_bad_package_rejected_before_prompt(self):
        self.package.write_bytes(b'tampered')
        with patch.object(native, 'read_protected_key', side_effect=AssertionError('unexpected prompt')):
            code, receipt = self.run_flow(self.args + ['--check-key-input'])
        self.assertEqual((code, receipt['error']), (2, 'PREPARATION_REJECTED'))

    def test_bad_config_rejected_before_prompt(self):
        self.config.write_bytes(b'{}')
        with patch.object(native, 'read_protected_key', side_effect=AssertionError('unexpected prompt')):
            code, receipt = self.run_flow(self.args + ['--check-key-input'])
        self.assertEqual(code, 2)

    def test_cli_errors_never_echo_unknown_or_secret_arguments(self):
        for extra in (['--key', CANARY.decode()], [CANARY.decode()], ['--url', CANARY.decode()]):
            with self.subTest(option=extra[0]):
                code, receipt = self.run_flow(self.args + extra)
                self.assertEqual((code, receipt['error']), (2, 'ARGUMENTS_REJECTED'))

    def test_errors_and_cancellation_never_emit_input(self):
        for error, code in ((OSError(CANARY.decode()), 2), (KeyboardInterrupt(), 130)):
            with self.subTest(kind=type(error).__name__), \
                    patch.object(native, 'read_protected_key', side_effect=error):
                result, receipt = self.run_flow(self.args + ['--check-key-input'])
                self.assertEqual(result, code)
                self.assertEqual(receipt['installation'], 'HELD')

    def test_no_protected_terminal_fails_closed(self):
        with patch.object(native, 'read_protected_key', side_effect=native.InputRejected()):
            code, receipt = self.run_flow(self.args + ['--check-key-input'])
        self.assertEqual(code, 2)

    def test_invalid_key_bytes_rejected_and_wiped(self):
        for suffix in (b'\nextra', b'\r', b'\x00', b'\x1b', b' ', b';id', b'$(id)', b'"', b'\xff'):
            secret = bytearray(CANARY + suffix)
            with self.subTest(suffix=suffix), patch.object(native, 'read_protected_key', return_value=secret):
                code, receipt = self.run_flow(self.args + ['--check-key-input'])
            self.assertEqual(code, 2)
            self.assertFalse(any(secret))

    def test_empty_and_oversized_key_rejected(self):
        for secret in (bytearray(), bytearray(b'a' * 4097)):
            with patch.object(native, 'read_protected_key', return_value=secret):
                code, _ = self.run_flow(self.args + ['--check-key-input'])
            self.assertEqual(code, 2)
            self.assertFalse(any(secret))

    def test_actual_cli_from_unrelated_directory_is_inert(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        command = [sys.executable, '-B', str(Path(native.__file__).resolve()), *self.args]
        self.assertNotIn(CANARY.decode(), ' '.join(command))
        result = subprocess.run(command, cwd=self.root, capture_output=True, timeout=5, shell=False)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)['installation'], 'HELD')
        self.assertEqual(result.stderr, b'')
        self.assertNotIn(CANARY, result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        if os.name == 'nt':
            result = subprocess.run(command + ['--check-key-input'], cwd=self.root,
                                    capture_output=True, timeout=5, shell=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(json.loads(result.stdout)['error'], 'PROTECTED_INPUT_REJECTED')
            self.assertEqual(result.stderr, b'')
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})


if __name__ == '__main__':
    unittest.main()
