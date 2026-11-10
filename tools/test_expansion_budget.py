import gzip
import hashlib
import io
import tarfile
import unittest
from unittest.mock import patch
from test_package_client import archive, pack
from preflight_client import inspect_package

class ExpansionBudgetTests(unittest.TestCase):
    def test_pax_metadata_counted_before_tar_parsing(self):
        source = archive()
        raw = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(source), mode='r:gz') as inp:
            with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT,
                              pax_headers={'comment': 'x' * 65537}) as out:
                for member in inp:
                    out.addfile(member, inp.extractfile(member))
        oversized = gzip.compress(raw.getvalue())
        with patch('package_client.MAX_TOTAL', 65536):
            with self.assertRaisesRegex(ValueError, 'expanded stream'):
                pack(oversized)

    def test_padding_and_concatenated_gzip_counted_in_both_paths(self):
        source = archive()
        candidate = pack(source)
        for blob, consumer in ((source, pack), (candidate, lambda b: inspect_package(b, hashlib.sha256(b).hexdigest()))):
            for oversized in (gzip.compress(gzip.decompress(blob) + b'\0' * 65537),
                              blob + gzip.compress(b'\0' * 65537)):
                with self.subTest(consumer=consumer, size=len(oversized)):
                    with patch('package_client.MAX_TOTAL', 65536):
                        with self.assertRaisesRegex(ValueError, 'expanded stream'):
                            consumer(oversized)

if __name__ == '__main__': unittest.main()
