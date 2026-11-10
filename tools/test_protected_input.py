"""Terminal contract fixtures; POSIX PTY test is explicitly platform gated."""
import copy
import os
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import protected_input as protected


CANARY = b'synthetic-terminal-canary'


class Terminal:
    ICRNL, INLCR, IGNCR, ISTRIP, IXON, IXOFF = (1, 2, 4, 8, 16, 32)
    ECHO, ECHONL, ICANON, IEXTEN = (1, 2, 4, 8)
    VMIN, VTIME, TCSAFLUSH = (0, 1, 2)

    def __init__(self):
        self.original = [63, 0, 0, 15, 0, 0, [0, 1]]
        self.current = copy.deepcopy(self.original)
        self.transitions = []

    def tcgetattr(self, fd):
        return copy.deepcopy(self.current)

    def tcsetattr(self, fd, when, attrs):
        self.transitions.append((when, copy.deepcopy(attrs)))
        self.current = copy.deepcopy(attrs)


class Tests(unittest.TestCase):
    def setUp(self):
        if os.name != 'posix':
            # Model only the mask API on Windows; no physical POSIX claim.
            for name, value in (('SIG_BLOCK', 0), ('SIG_SETMASK', 2)):
                patcher = patch.object(protected.signal, name, value, create=True)
                patcher.start()
                self.addCleanup(patcher.stop)
            patcher = patch.object(protected.signal, 'pthread_sigmask', return_value=set(), create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def invoke(self, values, error=None):
        terminal = Terminal()
        writes = []
        chunks = iter(bytes([v]) for v in values)

        def read(fd, size):
            self.assertEqual(size, 1)
            self.assertFalse(terminal.current[3] & (terminal.ECHO | terminal.ECHONL | terminal.ICANON))
            try:
                return next(chunks)
            except StopIteration:
                if error:
                    raise error
                return b''

        try:
            with patch.object(protected.os, 'read', side_effect=read), \
                    patch.object(protected.os, 'write', side_effect=lambda fd, value: writes.append(value)):
                return protected._read_terminal(42, terminal)
        finally:
            self.assertEqual(terminal.current, terminal.original)
            self.assertEqual(terminal.transitions[-1], (terminal.TCSAFLUSH, terminal.original))
            self.assertNotIn(CANARY, b''.join(writes))

    def test_hidden_prompt_and_restoration(self):
        value = self.invoke(CANARY + b'\n')
        self.assertEqual(value, bytearray(CANARY))
        protected.wipe(value)

    def test_input_error_restores_terminal(self):
        with self.assertRaises(OSError):
            self.invoke(CANARY, OSError('synthetic read failure'))

    def test_cancel_restores_terminal(self):
        with self.assertRaises(KeyboardInterrupt):
            self.invoke(CANARY, KeyboardInterrupt())

    def test_control_injection_rejected(self):
        for invalid in (b'\x00', b'\x1b', b'\t', b'\x7f', b';', b'$', b'\xff'):
            with self.subTest(value=invalid), self.assertRaises(protected.InputRejected):
                self.invoke(CANARY + invalid)

    def test_eof_empty_and_overflow_rejected(self):
        for value in (b'', b'\n', b'a' * 4097):
            with self.subTest(size=len(value)), self.assertRaises(protected.InputRejected):
                self.invoke(value)

    def test_enter_ends_input_and_pending_paste_is_flushed(self):
        # tcsetattr(TCSAFLUSH) is asserted by invoke; no remainder is consumed.
        value = self.invoke(CANARY + b'\nnot-part-of-key\n')
        self.assertEqual(value, bytearray(CANARY))
        protected.wipe(value)

    def test_refused_echo_disable_aborts_before_read(self):
        terminal = Terminal()
        with patch.object(terminal, 'tcgetattr', return_value=terminal.original), \
                patch.object(protected.os, 'read', side_effect=AssertionError('must not read')), \
                patch.object(protected.os, 'write', return_value=1), \
                self.assertRaises(protected.InputRejected):
            protected._read_terminal(42, terminal)
        self.assertEqual(terminal.current, terminal.original)

    def test_interrupted_restoration_retries_then_cancels(self):
        terminal = Terminal()
        apply_mode = terminal.tcsetattr
        attempts = []

        def set_mode(fd, when, attrs):
            if attrs == terminal.original:
                attempts.append(1)
                if len(attempts) == 1:
                    raise KeyboardInterrupt()
            apply_mode(fd, when, attrs)

        with patch.object(terminal, 'tcsetattr', side_effect=set_mode), \
                patch.object(protected.os, 'read', side_effect=[b'a', b'\n']), \
                patch.object(protected.os, 'write', return_value=1), \
                self.assertRaises(KeyboardInterrupt):
            protected._read_terminal(42, terminal)
        self.assertEqual(terminal.current, terminal.original)
        self.assertEqual(len(attempts), 2)

    def test_non_posix_fails_without_stdin_or_console_fallback(self):
        with patch.object(protected.os, 'name', 'nt'), \
                patch('builtins.input', side_effect=AssertionError('fallback forbidden')), \
                self.assertRaises(protected.InputRejected):
            protected.read_protected_key()

    def test_signal_handler_cancels(self):
        with self.assertRaises(KeyboardInterrupt):
            protected._cancel(signal.SIGTERM, None)

    def test_close_failure_wipes_returned_buffer_and_restores_handlers(self):
        value = bytearray(CANARY)
        system = SimpleNamespace(name='posix', O_RDWR=2, O_NOCTTY=4, O_CLOEXEC=8,
                                 open=Mock(return_value=42), isatty=lambda fd: True,
                                 tcgetpgrp=lambda fd: 7, getpgrp=lambda: 7,
                                 close=Mock(side_effect=OSError('close failed')))
        handlers = {n: object() for n in range(1, 6)}
        initial = handlers.copy()

        def set_handler(sig, handler):
            previous = handlers[sig]
            handlers[sig] = handler
            return previous

        signals = SimpleNamespace(SIGINT=1, SIGTERM=2, SIGHUP=3, SIGQUIT=4,
                                  SIGTSTP=5, signal=set_handler, pthread_sigmask=Mock())
        with patch.object(protected, 'os', system), patch.object(protected, 'signal', signals), \
                patch.dict('sys.modules', {'termios': Terminal()}), \
                patch.object(protected, '_read_terminal', return_value=value), \
                self.assertRaises(OSError):
            protected.read_protected_key()
        self.assertFalse(any(value))
        self.assertEqual(handlers, initial)

    @unittest.skipUnless(os.name == 'posix', 'requires POSIX PTY; Windows fixture checks are not physical terminal proof')
    def test_real_pty_echo_and_restoration(self):
        import pty
        import select
        import termios
        import threading

        master, slave = pty.openpty()
        original = termios.tcgetattr(slave)
        result = []

        def receive():
            try:
                result.append(protected._read_terminal(slave, termios))
            except BaseException as error:
                result.append(type(error).__name__)

        worker = threading.Thread(target=receive, daemon=True)
        try:
            worker.start()
            self.assertTrue(select.select([master], [], [], 2)[0])
            prompt = os.read(master, 1024)
            self.assertIn(b'Synthetic key', prompt)
            self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
            os.write(master, CANARY + b'\n')
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [bytearray(CANARY)])
            self.assertEqual(termios.tcgetattr(slave), original)
            self.assertTrue(select.select([master], [], [], 2)[0])
            self.assertNotIn(CANARY, os.read(master, 1024))
        finally:
            for value in result:
                protected.wipe(value)
            os.close(master)
            os.close(slave)


if __name__ == '__main__':
    unittest.main()
