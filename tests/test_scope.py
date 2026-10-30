import json, tempfile, unittest
from pathlib import Path
from grevora_recon.scope import ScopeError, load_scope, load_targets, normalize_target

class ScopeTests(unittest.TestCase):
    def setUp(self): self.roots=["example.com"]
    def test_root_and_subdomain(self):
        self.assertEqual(normalize_target("example.com",self.roots),"https://example.com/")
        self.assertEqual(normalize_target("https://api.example.com/v1",self.roots),"https://api.example.com/v1")
    def test_reject_suffix_attack(self):
        with self.assertRaises(ScopeError): normalize_target("https://example.com.attacker.test",self.roots)
    def test_reject_other_domain(self):
        with self.assertRaises(ScopeError): normalize_target("https://attacker.test",self.roots)
    def test_reject_ip_localhost_ftp(self):
        for t in ("http://127.0.0.1","http://localhost","ftp://example.com"):
            with self.subTest(target=t), self.assertRaises(ScopeError): normalize_target(t,self.roots)
    def test_reject_credentials(self):
        with self.assertRaises(ScopeError): normalize_target("https://user:pass@example.com",self.roots)
    def test_load_files(self):
        with tempfile.TemporaryDirectory() as d:
            s=Path(d)/"scope.json"; t=Path(d)/"targets.txt"
            s.write_text(json.dumps({"authorized_domains":["Example.com"]}))
            t.write_text("# comment\nexample.com\nhttps://api.example.com/health\n")
            roots=load_scope(s); self.assertEqual(roots,["example.com"])
            self.assertEqual(len(load_targets(t,roots)),2)
    def test_empty_scope_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            s=Path(d)/"scope.json"; s.write_text('{"authorized_domains":[]}')
            with self.assertRaises(ScopeError): load_scope(s)

if __name__=="__main__": unittest.main()
