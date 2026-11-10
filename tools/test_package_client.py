import hashlib
import io
import json
import tarfile
import unittest
from pathlib import Path
import subprocess
import sys
import tempfile
from package_client import FILES, candidate_bytes

SHA = 'a' * 40
AGENT = b'test-only inert fixture, not an executable'

def archive(extra=(), metadata=None, omit=None):
    metadata = metadata if metadata is not None else ('source_sha=' + SHA + '\ntarget=linux/amd64\ncgo=disabled\nrelease=NOT_AUTHORIZED\ninstallation=NOT_AUTHORIZED\n')
    entries = [(n, AGENT if n == 'felixwatch-agent' else b'fixture') for n in FILES if n != omit]
    entries += [('BUILD-METADATA.txt', metadata.encode()), ('felixwatch-collector', b'server excluded')] + list(extra)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as tar:
        for name, body in entries:
            member = tarfile.TarInfo(name)
            if body is None:
                member.type = tarfile.SYMTYPE
                member.linkname = '/outside'
                tar.addfile(member)
            else:
                member.size = len(body)
                tar.addfile(member, io.BytesIO(body))
    return stream.getvalue()

def pack(data, **kw):
    return candidate_bytes(data, kw.get('archive_sha', hashlib.sha256(data).hexdigest()), kw.get('agent_sha', hashlib.sha256(AGENT).hexdigest()), kw.get('source_sha', SHA))

class Tests(unittest.TestCase):
    def test_allowlist_and_determinism(self):
        source = archive()
        first = pack(source)
        self.assertEqual(first, pack(source))
        with tarfile.open(fileobj=io.BytesIO(first), mode='r:gz') as t:
            self.assertEqual(set(t.getnames()), set(FILES) | {'CANDIDATE-MANIFEST.json', 'SHA256SUMS'})
            self.assertNotIn('felixwatch-collector', t.getnames())
            manifest = json.load(t.extractfile('CANDIDATE-MANIFEST.json'))
            self.assertFalse(manifest['public_publication_authorized'])
            self.assertFalse(manifest['installation_authorized'])
            for m in t:
                self.assertEqual((m.uid, m.gid, m.mtime), (0, 0, 0))
                self.assertTrue(m.isfile())
    def test_member_budget(self):
        with self.assertRaises(ValueError):
            pack(archive([('padding%d' % i,b'') for i in range(130)]))
    def test_cli_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = archive()
            root = Path(tmp)
            (root/'in.tar.gz').write_bytes(source)
            output = root/'out.tar.gz'
            output.write_bytes(b'preserve')
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('package_client.py')), str(root/'in.tar.gz'), str(output), '--archive-sha256', hashlib.sha256(source).hexdigest(), '--agent-sha256', hashlib.sha256(AGENT).hexdigest(), '--source-sha', SHA], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_bytes(), b'preserve')
    def test_wrong_archive_digest(self):
        with self.assertRaises(ValueError): pack(archive(), archive_sha='0'*64)
    def test_wrong_agent_digest(self):
        with self.assertRaises(ValueError): pack(archive(), agent_sha='0'*64)
    def test_missing_client_file(self):
        with self.assertRaises(ValueError): pack(archive(omit='felixwatch-agent'))
    def test_traversal(self):
        for name in ('../oops', '/oops', 'a/../oops', 'a\\oops'):
            with self.subTest(name=name), self.assertRaises(ValueError): pack(archive([(name,b'x')]))
    def test_symlink(self):
        with self.assertRaises(ValueError): pack(archive([('evil',None)]))
    def test_duplicate(self):
        with self.assertRaises(ValueError): pack(archive([('felixwatch-agent',AGENT)]))
    def test_source_mismatch(self):
        with self.assertRaises(ValueError): pack(archive(), source_sha='b'*40)
    def test_metadata_duplicate(self):
        with self.assertRaises(ValueError): pack(archive(metadata='source_sha='+SHA+'\nsource_sha='+SHA))
    def test_bad_revision(self):
        with self.assertRaises(ValueError): pack(archive(), source_sha='../invalid')
    def test_expanded_budget(self):
        with self.assertRaises(ValueError): pack(archive([('oversized',b'x'*(16*1024*1024+1))]))

if __name__ == '__main__': unittest.main()
