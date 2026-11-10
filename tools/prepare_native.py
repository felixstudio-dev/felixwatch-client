"""PRIVATE offline native preparation. Never installs, authenticates or activates."""
import argparse
import json
import os
from pathlib import Path
import stat

from handoff_snapshot import prepare
from package_client import MAX_ARCHIVE
from protected_input import InputRejected, read_protected_key, validate_key, wipe


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal error includes attacker-controlled argv values.
        raise InputRejected()


def read_bounded(path, limit):
    # Read retained bytes, never execute/extract or hand these paths to installer.
    if not stat.S_ISREG(path.lstat().st_mode):
        raise InputRejected()
    flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InputRejected()
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise InputRejected()
    return value


def main(argv=None):
    receipt = {'preparation': 'REJECTED', 'key_input': 'NOT_REQUESTED',
               'provisioning': 'HELD', 'installation': 'HELD', 'activation': 'HELD'}
    key = None
    phase = 'ARGUMENTS_REJECTED'
    code = 2
    try:
        parser = SafeParser(description=__doc__, allow_abbrev=False)
        parser.add_argument('--package', type=Path, required=True)
        parser.add_argument('--package-sha256', required=True)
        parser.add_argument('--config', type=Path, required=True)
        parser.add_argument('--config-sha256', required=True)
        parser.add_argument('--check-key-input', action='store_true',
                            help='synthetic input only; discarded, never authenticated')
        args = parser.parse_args(argv)
        phase = 'PREPARATION_REJECTED'
        snapshot = prepare(read_bounded(args.package, MAX_ARCHIVE),
                           read_bounded(args.config, 65536),
                           args.package_sha256, args.config_sha256)
        receipt['preparation'] = 'PASS'
        # This is integrity evidence only. No key, key hash or caller text in receipt.
        receipt['package_sha256'] = snapshot.package_sha256
        receipt['config_sha256'] = snapshot.config_sha256
        if args.check_key_input:
            phase = 'PROTECTED_INPUT_REJECTED'
            receipt['key_input'] = 'REJECTED'
            key = read_protected_key()
            validate_key(key)
            receipt['key_input'] = 'FORMAT_ONLY_NOT_AUTHENTICATED'
        code = 3  # Preparation is not installation success or FAC acceptance.
    except KeyboardInterrupt:
        receipt['error'] = 'CANCELLED'
        code = 130
    except Exception:
        # Underlying JSON, I/O, terminal, parser and validation exceptions may
        # contain input. Do not print, chain, log or return their messages.
        receipt['error'] = phase
    finally:
        wipe(key)  # Best effort, not guaranteed process-memory erasure.
    print(json.dumps(receipt, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
