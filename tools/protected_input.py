"""Bounded POSIX controlling-terminal input. No stdin fallback or persistence."""
import os
import signal

MAX_KEY_BYTES = 4096
_ALLOWED = frozenset(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-')


class InputRejected(Exception):
    """Categorical failure; never carries input bytes."""


def wipe(value):
    if isinstance(value, bytearray):
        value[:] = b'\0' * len(value)


def validate_key(value):
    # Local transport hygiene only, NOT an admitted FAC key grammar or authority.
    if type(value) is not bytearray or not 1 <= len(value) <= MAX_KEY_BYTES:
        raise InputRejected()
    if any(byte not in _ALLOWED for byte in value):
        raise InputRejected()


def _cancel(signum, frame):
    raise KeyboardInterrupt()


def _cancellation_signals():
    return tuple(getattr(signal, name) for name in
                 ('SIGINT', 'SIGTERM', 'SIGHUP', 'SIGQUIT', 'SIGTSTP')
                 if hasattr(signal, name))


def _restore_terminal(fd, terminal, original):
    previous_mask = None
    interrupted = False
    try:
        # Defer handled signals until echo/canonical mode is restored. Retry a
        # recoverable interruption even at mask acquisition, never indefinitely.
        for attempt in range(3):
            try:
                if previous_mask is None:
                    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _cancellation_signals())
                terminal.tcsetattr(fd, terminal.TCSAFLUSH, original)
                break
            except (InterruptedError, KeyboardInterrupt):
                interrupted = True
        else:
            raise InputRejected()
    finally:
        if previous_mask is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    if interrupted:
        raise KeyboardInterrupt()


def _read_terminal(fd, terminal):
    """Own mode restoration even on I/O failure or cancellation."""
    original = terminal.tcgetattr(fd)
    hidden = original[:]
    hidden[6] = original[6][:]
    hidden[0] &= ~(terminal.ICRNL | terminal.INLCR | terminal.IGNCR |
                   terminal.ISTRIP | terminal.IXON | terminal.IXOFF)
    hidden[3] &= ~(terminal.ECHO | terminal.ECHONL | terminal.ICANON | terminal.IEXTEN)
    hidden[6][terminal.VMIN] = 1
    hidden[6][terminal.VTIME] = 0
    value = bytearray()
    success = False
    try:
        # Flush pretyped input before prompt; do not accept shell/pipeline input.
        terminal.tcsetattr(fd, terminal.TCSAFLUSH, hidden)
        actual = terminal.tcgetattr(fd)
        if actual[3] & (terminal.ECHO | terminal.ECHONL | terminal.ICANON):
            raise InputRejected()
        os.write(fd, b'Synthetic key input check (offline; no authentication): ')
        while True:
            char = os.read(fd, 1)
            if char in (b'\r', b'\n'):
                break
            if len(char) != 1 or char[0] not in _ALLOWED or len(value) >= MAX_KEY_BYTES:
                raise InputRejected()
            value.extend(char)
        validate_key(value)
        success = True
        return value
    finally:
        try:
            # Discard pending pasted input before restoring echo; never replay it
            # to the shell. Enter terminates one input; multiline isn't a token.
            _restore_terminal(fd, terminal, original)
            os.write(fd, b'\n')
        except BaseException:
            wipe(value)
            raise
        finally:
            if not success:
                wipe(value)


def read_protected_key():
    if os.name != 'posix' or not hasattr(signal, 'pthread_sigmask'):
        raise InputRejected()
    import termios
    fd = None
    handlers = {}
    value = None
    try:
        fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        if not os.isatty(fd) or os.tcgetpgrp(fd) != os.getpgrp():
            raise InputRejected()
        # Catch normal cancellation/termination/suspend before changing modes.
        # SIGKILL, host death and hostile same-user/root observers are out of scope.
        for sig in _cancellation_signals():
            handlers[sig] = signal.signal(sig, _cancel)
        value = _read_terminal(fd, termios)
        return value
    finally:
        try:
            try:
                if fd is not None:
                    os.close(fd)
            finally:
                for sig, handler in handlers.items():
                    signal.signal(sig, handler)
        except BaseException:
            wipe(value)
            raise
