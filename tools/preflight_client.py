"""Read-only candidate integrity/configuration preflight; NEVER installs or authorizes."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from urllib.parse import urlsplit
from package_client import FILES, MAX_ARCHIVE, MAX_MEMBER, MAX_TOTAL, checked_hex, bounded_tar_stream


def strict_object(pairs):
    result = {}
    folded = set()
    for key, value in pairs:
        if key.casefold() in folded:
            raise ValueError('duplicate or case-aliased JSON key')
        folded.add(key.casefold())
        result[key] = value
    return result


CONFIG_FIELDS = {'collector_url', 'agent_id', 'customer_id', 'infrastructure_id',
                 'server_id', 'secret_env', 'interval_seconds', 'queue_path',
                 'queue_max_bytes', 'allow_insecure_http', 'sites', 'services'}
SITE_FIELDS = {'site_id', 'url', 'expected_status', 'timeout_seconds'}
SERVICE_FIELDS = {'service_id', 'pid_file', 'expected_comm', 'essential'}


def scalar_types(obj, strings=(), integers=(), booleans=()):
    """Check present scalar fields for the Linux/amd64 Go config contract.

    Missing optional fields retain existing default handling. Explicit nulls
    are rejected by this stricter offline preparation boundary. This is type
    validation only, not semantic acceptance, collector scope or authority.
    """
    for names, kind in ((strings, str), (integers, int), (booleans, bool)):
        for name in names:
            if name not in obj:
                continue
            value = obj[name]
            if type(value) is not kind:
                raise ValueError('configuration scalar has wrong type')
            if kind is int and not -(2**63) <= value < 2**63:
                raise ValueError('configuration integer outside Linux/amd64 range')


def canonical_object(obj, fields):
    if not isinstance(obj, dict) or set(obj) - fields:
        raise ValueError('unknown or non-canonical configuration field')


def validate_config(blob):
    if len(blob) > 65536:
        raise ValueError('configuration too large')
    cfg = json.loads(blob, object_pairs_hook=strict_object)
    canonical_object(cfg, CONFIG_FIELDS)
    scalar_types(cfg,
                 strings=('collector_url', 'agent_id', 'customer_id',
                          'infrastructure_id', 'server_id', 'secret_env', 'queue_path'),
                 integers=('interval_seconds', 'queue_max_bytes'),
                 booleans=('allow_insecure_http',))
    url = urlsplit(cfg.get('collector_url', ''))
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment:
        raise ValueError('collector must be HTTPS without credentials or fragment')
    if url.hostname.endswith('.invalid'):
        raise ValueError('replace placeholder collector before deployment')
    if cfg.get('allow_insecure_http') is not False:
        raise ValueError('insecure HTTP must be explicitly disabled')
    for field in ('agent_id', 'customer_id', 'infrastructure_id', 'server_id'):
        val = cfg.get(field)
        if not isinstance(val, str) or not val or 'REPLACE_' in val or 'demo' in val:
            raise ValueError('missing or placeholder identity')
    if not re.fullmatch(r'[A-Z_][A-Z0-9_]{0,127}', cfg.get('secret_env', '')):
        raise ValueError('secret must be referenced by environment variable name')
    if any(k in cfg for k in ('secret', 'token', 'password', 'api_key')):
        raise ValueError('inline credentials forbidden')
    for key in ('sites', 'services'):
        if not isinstance(cfg.get(key), list):
            raise ValueError('explicit site and service lists required')
    for site in cfg['sites']:
        canonical_object(site, SITE_FIELDS)
        scalar_types(site, strings=('site_id', 'url'),
                     integers=('expected_status', 'timeout_seconds'))
        u = urlsplit(site.get('url', ''))
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment:
            raise ValueError('site requires credential-free HTTPS URL')
    for service in cfg['services']:
        canonical_object(service, SERVICE_FIELDS)
        scalar_types(service, strings=('service_id', 'pid_file', 'expected_comm'),
                     booleans=('essential',))
    return cfg


def inspect_package(blob, expected_sha256):
    checked_hex(expected_sha256, 64)
    if len(blob) > MAX_ARCHIVE or hashlib.sha256(blob).hexdigest() != expected_sha256:
        raise ValueError('candidate digest or size mismatch')
    expected = set(FILES) | {'CANDIDATE-MANIFEST.json', 'SHA256SUMS'}
    data, total = {}, 0
    with tarfile.open(fileobj=bounded_tar_stream(blob), mode='r:') as tar:
        for member in tar:
            if member.name not in expected or member.name in data or not member.isfile():
                raise ValueError('unexpected, duplicate or non-regular member')
            total += member.size
            if member.size < 0 or member.size > MAX_MEMBER or total > MAX_TOTAL:
                raise ValueError('archive expanded size exceeds budget')
            data[member.name] = tar.extractfile(member).read()
    if set(data) != expected:
        raise ValueError('incomplete candidate')
    manifest = json.loads(data['CANDIDATE-MANIFEST.json'], object_pairs_hook=strict_object)
    if not isinstance(manifest, dict) or manifest.get('schema_version') != 1:
        raise ValueError('unsupported manifest')
    if set(manifest.get('files', {})) != set(FILES):
        raise ValueError('manifest file set mismatch')
    for name in FILES:
        entry = manifest['files'][name]
        if entry.get('sha256') != hashlib.sha256(data[name]).hexdigest() or entry.get('bytes') != len(data[name]):
            raise ValueError('manifest payload mismatch')
    checksum_names = sorted(set(data) - {'SHA256SUMS'})
    expected_checksums = ''.join(hashlib.sha256(data[n]).hexdigest() + '  ' + n + '\n' for n in checksum_names).encode()
    if data['SHA256SUMS'] != expected_checksums:
        raise ValueError('checksum file mismatch')
    return {'integrity': 'PASS', 'installation': 'HELD',
            'reason': 'Integrity and config checks never grant installation authority.',
            'source_sha': manifest.get('source_sha'), 'state': manifest.get('state')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('candidate', type=Path)
    p.add_argument('--sha256', required=True, help='trusted digest from independently reviewed receipt')
    p.add_argument('--config', type=Path, required=True)
    a = p.parse_args()
    with a.candidate.open('rb') as f:
        result = inspect_package(f.read(MAX_ARCHIVE + 1), a.sha256)
    with a.config.open('rb') as f:
        validate_config(f.read(65537))
    result['configuration_structure'] = 'PASS_NOT_COLLECTOR_SCOPE_ACCEPTANCE'
    print(json.dumps(result, sort_keys=True))
    return 3  # Deliberately not an installer success code; candidate is still held.


if __name__ == '__main__':
    raise SystemExit(main())
