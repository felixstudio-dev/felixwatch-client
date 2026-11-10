from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest
from handoff_snapshot import prepare, verify_for_review
from test_package_client import archive, pack
from test_preflight_client import CONFIG
from package_client import MAX_ARCHIVE


def digest(b): return hashlib.sha256(b).hexdigest()

class Tests(unittest.TestCase):
    def setUp(self):
        self.p = pack(archive())
        self.c = json.dumps(CONFIG).encode()
    def snapshot(self): return prepare(self.p,self.c,digest(self.p),digest(self.c))
    def test_remains_held(self):
        self.assertEqual(verify_for_review(self.snapshot())['installation'],'HELD')
    def test_mutating_original_cannot_change_retained_bytes(self):
        p,c=bytearray(self.p),bytearray(self.c)
        s=prepare(p,c,digest(p),digest(c));p[:]=b'changed';c[:]=b'changed'
        self.assertEqual(s.package,self.p);self.assertEqual(s.config,self.c)
        self.assertEqual(verify_for_review(s)['integrity'],'PASS')
    def test_frozen(self):
        with self.assertRaises(FrozenInstanceError): self.snapshot().config=b'new'
    def test_wrong_config_digest(self):
        with self.assertRaises(ValueError): prepare(self.p,self.c,digest(self.p),'0'*64)
    def test_wrong_package_digest(self):
        with self.assertRaises(ValueError): prepare(self.p,self.c,'0'*64,digest(self.c))
    def test_tampered_reconstruction_rejected(self):
        with self.assertRaises(ValueError): verify_for_review(replace(self.snapshot(),config=b'{}'))
    def test_insecure_config_even_with_digest_rejected(self):
        c=json.dumps(dict(CONFIG,allow_insecure_http=True)).encode()
        with self.assertRaises(ValueError): prepare(self.p,c,digest(self.p),digest(c))
    def test_path_not_accepted(self):
        with self.assertRaises(ValueError): prepare('/tmp/input',self.c,digest(self.p),digest(self.c))
    def test_oversized_package_rejected_before_digest(self):
        with self.assertRaisesRegex(ValueError,'size budget'):
            prepare(bytearray(MAX_ARCHIVE+1),self.c,'0'*64,'0'*64)
    def test_oversized_config_rejected_before_digest(self):
        with self.assertRaisesRegex(ValueError,'size budget'):
            prepare(self.p,bytearray(65537),'0'*64,'0'*64)
    def test_custom_buffer_hooks_not_accepted(self):
        class Custom(bytearray):
            def __len__(self): raise AssertionError('caller hook executed')
            def __bytes__(self): raise AssertionError('caller hook executed')
        for p,c in ((Custom(self.p),self.c),(self.p,Custom(self.c))):
            with self.assertRaisesRegex(ValueError,'byte buffers required'):
                prepare(p,c,'0'*64,'0'*64)

if __name__=='__main__': unittest.main()
