import copy
import hashlib
import io
import json
import tarfile
import unittest
from preflight_client import inspect_package, validate_config
from test_package_client import archive, pack

CONFIG = {'collector_url':'https://collector.example.com', 'allow_insecure_http':False,
 'agent_id':'agent-01','customer_id':'customer-01','infrastructure_id':'infra-01',
 'server_id':'server-01','secret_env':'FELIXWATCH_AGENT_SECRET','sites':[],'services':[]}

class Tests(unittest.TestCase):
    def test_valid_remains_held(self):
        blob = pack(archive())
        result = inspect_package(blob, hashlib.sha256(blob).hexdigest())
        self.assertEqual(result['installation'],'HELD')
        self.assertEqual(result['integrity'],'PASS')
    def test_modified_digest(self):
        with self.assertRaises(ValueError): inspect_package(pack(archive()),'0'*64)
    def test_modified_payload_even_with_new_outer_digest(self):
        original = pack(archive())
        output = io.BytesIO()
        with tarfile.open(fileobj=io.BytesIO(original),mode='r:gz') as src, tarfile.open(fileobj=output,mode='w:gz') as dst:
            for m in src:
                body = src.extractfile(m).read()
                if m.name == 'felixwatch-agent': body = b'tampered'
                m.size = len(body)
                dst.addfile(m,io.BytesIO(body))
        blob=output.getvalue()
        with self.assertRaises(ValueError): inspect_package(blob,hashlib.sha256(blob).hexdigest())
    def test_go_case_alias_overrides_rejected(self):
        for key, value in (('COLLECTOR_URL', 'http://127.0.0.1:8090'),
                           ('ALLOW_INSECURE_HTTP', True)):
            c=copy.deepcopy(CONFIG); c[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_config(json.dumps(c).encode())
    def test_noncanonical_single_key_rejected(self):
        c=copy.deepcopy(CONFIG); c['COLLECTOR_URL']=c.pop('collector_url')
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_unknown_top_level_key_rejected(self):
        c=copy.deepcopy(CONFIG); c['unrecognized_option']=True
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_site_alias_override_rejected(self):
        c=copy.deepcopy(CONFIG)
        c['sites']=[{'site_id':'site-1','url':'https://example.com', 'URL':'http://127.0.0.1:8080'}]
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_nested_unknown_or_noncanonical_rejected(self):
        for field, item in (('sites', {'site_id':'site-1','url':'https://example.com','foo':1}),
                            ('sites', {'site_id':'site-1','URL':'https://example.com'}),
                            ('services', {'SERVICE_ID':'service-1'}),
                            ('services', {'service_id':'service-1','foo':1}),
                            ('services', {'service_id':'service-1','SERVICE_ID':'service-2'})):
            c=copy.deepcopy(CONFIG);c[field]=[item]
            with self.subTest(field=field,item=item), self.assertRaises(ValueError):
                validate_config(json.dumps(c).encode())
    def test_valid_config(self): validate_config(json.dumps(CONFIG).encode())
    def test_http_rejected(self):
        for url in ('http://127.0.0.1:8090','https://user:pass@host','https://host/#x','https://collector.invalid'):
            c=copy.deepcopy(CONFIG); c['collector_url']=url
            with self.subTest(url=url), self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_placeholder_identity(self):
        c=copy.deepcopy(CONFIG);c['agent_id']='REPLACE_AGENT'
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_inline_secret(self):
        c=copy.deepcopy(CONFIG);c['secret']='fixture'
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_duplicate_key(self):
        with self.assertRaises(ValueError): validate_config(b'{"sites":[],"sites":[]}')
    def test_insecure_flag_required(self):
        for v in (True,None,'false',0):
            c=copy.deepcopy(CONFIG);c['allow_insecure_http']=v
            with self.subTest(v=v), self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_explicit_lists_required(self):
        c=copy.deepcopy(CONFIG);del c['sites']
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())
    def test_site_http_rejected(self):
        c=copy.deepcopy(CONFIG);c['sites']=[{'url':'http://example.com'}]
        with self.assertRaises(ValueError): validate_config(json.dumps(c).encode())

if __name__ == '__main__': unittest.main()
