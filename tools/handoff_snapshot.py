"""Offline immutable handoff input. No install, extraction, execution or authority."""
from dataclasses import dataclass
import hashlib
from package_client import MAX_ARCHIVE, checked_hex
from preflight_client import inspect_package, validate_config


@dataclass(frozen=True)
class Snapshot:
    package: bytes
    config: bytes
    package_sha256: str
    config_sha256: str


def prepare(package, config, package_sha256, config_sha256):
    # Copy mutable buffers BEFORE validation. Callers must consume these exact
    # retained bytes, never reopen a pathname checked earlier.
    if type(package) not in (bytes, bytearray) or type(config) not in (bytes, bytearray):
        raise ValueError('byte buffers required')
    # Reject oversized input before allocating immutable copies. Exact builtin
    # types avoid overridden length/conversion hooks in caller-defined subclasses.
    if len(package) > MAX_ARCHIVE or len(config) > 65536:
        raise ValueError('snapshot input exceeds size budget')
    package, config = bytes(package), bytes(config)
    checked_hex(config_sha256, 64)
    if hashlib.sha256(config).hexdigest() != config_sha256:
        raise ValueError('configuration differs from independently reviewed digest')
    inspect_package(package, package_sha256)
    validate_config(config)
    return Snapshot(package, config, package_sha256, config_sha256)


def verify_for_review(snapshot):
    # Recheck even manually constructed or reconstructed objects. A dataclass is
    # not an authentication boundary, and this function never grants authority.
    if not isinstance(snapshot, Snapshot):
        raise ValueError('snapshot required')
    validated = prepare(snapshot.package, snapshot.config,
                        snapshot.package_sha256, snapshot.config_sha256)
    return {'integrity': 'PASS', 'installation': 'HELD',
            'package_sha256': validated.package_sha256,
            'config_sha256': validated.config_sha256,
            'scope': 'offline retained bytes only; no installer handoff authorized'}
