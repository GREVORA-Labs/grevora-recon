import tempfile, unittest
from grevora_recon.checks import render_html
from grevora_recon.report import write_reports

class ReportTests(unittest.TestCase):
    def test_html_escapes_untrusted_content(self):
        r={"results":[{"target":"<script>alert(1)</script>","status":"ok","http_status":200,
        "findings":[{"severity":"low","id":"X","message":"<img src=x onerror=alert(1)>","evidence":{"x":"<script>"}}]}]}
        html=render_html(r)
        self.assertNotIn("<script>",html); self.assertIn("&lt;script&gt;",html); self.assertIn("&lt;img",html)
    def test_writes_reports(self):
        with tempfile.TemporaryDirectory() as d:
            a,b=write_reports([{"target":"https://example.com/","status":"ok","http_status":200,"findings":[]}],d)
            self.assertTrue(a.exists() and b.exists()); self.assertIn("GREVORA Recon",b.read_text())

if __name__=="__main__": unittest.main()
