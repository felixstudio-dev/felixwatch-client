"""Create a deterministic PRIVATE client-only candidate from a reviewed CI bundle.

No build, install, network, execution, signing, version admission or publication.
The expected digest values must come from independently reviewed provenance.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile

FILES = {
    'felixwatch-agent': 0o755,
    'configs/agent.example.json': 0o644,
    'scripts/install-linux.sh': 0o755,
    'scripts/uninstall-linux.sh': 0o755,
    'systemd/felixwatch-agent.service': 0o644,
    'systemd/felixwatch-agent.systemd219.service': 0o644,
}
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked_hex(value, length):
    if not re.fullmatch('[0-9a-f]{%d}' % length, value):
        raise ValueError('invalid digest or source revision')
    return value


def bounded_tar_stream(source):
    """Bound every decompressed byte, including hidden PAX headers and padding."""
    with gzip.GzipFile(fileobj=io.BytesIO(source), mode='rb') as stream:
        raw = stream.read(MAX_TOTAL + 1)
    if len(raw) > MAX_TOTAL:
        raise ValueError('expanded stream exceeds budget')
    return io.BytesIO(raw)


def candidate_bytes(source, archive_sha256, agent_sha256, source_sha):
    checked_hex(archive_sha256, 64)
    checked_hex(agent_sha256, 64)
    checked_hex(source_sha, 40)
    if len(source) > MAX_ARCHIVE or digest(source) != archive_sha256:
        raise ValueError('archive size or digest mismatch')
    data = {}
    total = 0
    seen = set()
    with tarfile.open(fileobj=bounded_tar_stream(source), mode='r:') as archive:
        for index, member in enumerate(archive):
            if index >= 128:
                raise ValueError("too many archive members")
            name = member.name
            if name.startswith('./'):
                name = name[2:]
            if name in ('', '.') and member.isdir():
                continue
            if name.startswith('/') or '\\' in name or '..' in name.split('/'):
                raise ValueError('unsafe member name')
            if name in seen:
                raise ValueError('duplicate archive member')
            seen.add(name)
            if not (member.isfile() or member.isdir()):
                raise ValueError('links and special files are forbidden')
            if member.isdir():
                continue
            total += member.size
            if member.size < 0 or member.size > MAX_MEMBER or total > MAX_TOTAL:
                raise ValueError('expanded archive exceeds budget')
            # Ignore server-only content. Never extract paths to the filesystem.
            if name in FILES or name == 'BUILD-METADATA.txt':
                data[name] = archive.extractfile(member).read()
    if set(data) != set(FILES) | {'BUILD-METADATA.txt'}:
        raise ValueError('missing required client files or provenance')
    metadata = data.pop('BUILD-METADATA.txt').decode('utf-8')
    fields = {}
    for line in metadata.splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            if key in fields:
                raise ValueError('duplicate metadata field')
            fields[key] = value
    required = {'source_sha': source_sha, 'target': 'linux/amd64', 'cgo': 'disabled',
                'release': 'NOT_AUTHORIZED', 'installation': 'NOT_AUTHORIZED'}
    if any(fields.get(k) != v for k, v in required.items()):
        raise ValueError('source metadata mismatch')
    if digest(data['felixwatch-agent']) != agent_sha256:
        raise ValueError('agent digest mismatch')
    manifest = {
        'schema_version': 1, 'component': 'felixwatch-client-linux-amd64',
        'source_sha': source_sha, 'input_archive_sha256': archive_sha256,
        'state': 'PRIVATE_CANDIDATE_NOT_RELEASED',
        'physical_validation': False, 'installation_authorized': False,
        'public_publication_authorized': False,
        'files': {n: {'sha256': digest(b), 'bytes': len(b)} for n, b in sorted(data.items())},
    }
    data['CANDIDATE-MANIFEST.json'] = (json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode()
    data['SHA256SUMS'] = ''.join('%s  %s\n' % (digest(b), n) for n, b in sorted(data.items())).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.USTAR_FORMAT) as output:
        for name, content in sorted(data.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = FILES.get(name, 0o644)
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ''
            output.addfile(info, io.BytesIO(content))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode='wb', filename='', mtime=0) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input_archive', type=Path)
    p.add_argument('output_archive', type=Path)
    p.add_argument('--archive-sha256', required=True)
    p.add_argument('--agent-sha256', required=True)
    p.add_argument('--source-sha', required=True)
    a = p.parse_args()
    with a.input_archive.open('rb') as source:
        payload = source.read(MAX_ARCHIVE + 1)
    result = candidate_bytes(payload, a.archive_sha256, a.agent_sha256, a.source_sha)
    # Exclusive creation: never overwrite a previous candidate or follow output links.
    with a.output_archive.open('xb') as output:
        output.write(result)
    print(digest(result) + '  ' + a.output_archive.name)


if __name__ == '__main__':
    main()
