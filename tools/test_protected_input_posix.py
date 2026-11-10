"""Real disposable POSIX controlling-terminal tests; synthetic input only."""
import json
import os
import signal
import time
import unittest

import protected_input as protected


@unittest.skipUnless(os.name == 'posix', 'requires isolated POSIX controlling PTYs')
class PosixTests(unittest.TestCase):
    def exercise(self, payload=b'synthetic-pty-only', cancel=None, rejection=False,
                 controlling=True, newline=True):
        import fcntl
        import pty
        import select
        import termios

        master, slave = pty.openpty()
        result_read, result_write = os.pipe()
        original = termios.tcgetattr(slave)
        pid = os.fork()
        if pid == 0:
            os.close(master)
            os.close(result_read)
            os.setsid()
            if controlling:
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            before_handlers = {s: signal.getsignal(s) for s in protected._cancellation_signals()}
            before_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            # Hard child deadline, independent of the parent polling deadline.
            signal.alarm(5)
            value = None
            status = 'UNEXPECTED'
            try:
                value = protected.read_protected_key()
                status = 'FORMAT_OK' if value == bytearray(payload) else 'VALUE_MISMATCH'
            except KeyboardInterrupt:
                status = 'CANCELLED'
            except (protected.InputRejected, OSError):
                status = 'REJECTED'
            finally:
                protected.wipe(value)
                result = {'status': status,
                          'handlers_restored': all(signal.getsignal(s) == h for s, h in before_handlers.items()),
                          'mask_restored': signal.pthread_sigmask(signal.SIG_BLOCK, []) == before_mask,
                          'buffer_wiped': value is None or not any(value)}
                os.write(result_write, json.dumps(result).encode('ascii'))
                os._exit(0)

        os.close(result_write)
        output = bytearray()
        reaped = False
        try:
            if controlling:
                deadline = time.monotonic() + 3
                while b'authentication): ' not in output:
                    self.assertLess(time.monotonic(), deadline, 'prompt deadline exceeded')
                    if select.select([master], [], [], 0.05)[0]:
                        output.extend(os.read(master, 1024))
                self.assertFalse(termios.tcgetattr(slave)[3] & (termios.ECHO | termios.ECHONL))
                os.write(master, payload + (b'\n' if newline and cancel is None else b''))
                if cancel is not None:
                    os.kill(pid, cancel)  # Only the child created by this test.
            deadline = time.monotonic() + 3
            while True:
                done, wait_status = os.waitpid(pid, os.WNOHANG)
                if done:
                    reaped = True
                    self.assertEqual(wait_status, 0)
                    break
                self.assertLess(time.monotonic(), deadline, 'child deadline exceeded')
                if select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 1024))
            while select.select([master], [], [], 0)[0]:
                output.extend(os.read(master, 1024))
            result = json.loads(os.read(result_read, 2048).decode('ascii'))
            expected = 'CANCELLED' if cancel else ('REJECTED' if rejection else 'FORMAT_OK')
            self.assertEqual(result['status'], expected)
            self.assertTrue(result['handlers_restored'])
            self.assertTrue(result['mask_restored'])
            self.assertTrue(result['buffer_wiped'])
            self.assertEqual(termios.tcgetattr(slave), original)
            self.assertFalse(select.select([slave], [], [], 0)[0], 'pending input not flushed')
            if payload:
                self.assertNotIn(payload, output)
        finally:
            if not reaped:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)
            for fd in (master, slave, result_read):
                os.close(fd)

    def test_controlling_terminal_success(self):
        self.exercise()

    def test_handled_signals_restore_terminal_handlers_and_mask(self):
        for sig in protected._cancellation_signals():
            with self.subTest(signal=sig.name):
                self.exercise(cancel=sig)

    def test_control_byte_rejection_restores_terminal(self):
        self.exercise(payload=b'synthetic-only\x1b', rejection=True)

    def test_empty_input_rejection_restores_terminal(self):
        self.exercise(payload=b'', rejection=True)

    def test_no_controlling_terminal_fails_closed(self):
        self.exercise(controlling=False, rejection=True)


if __name__ == '__main__':
    unittest.main()
