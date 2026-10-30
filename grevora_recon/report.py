import json
from pathlib import Path
from .checks import render_html

def write_reports(results, output_dir):
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True)
    report={"tool":"GREVORA Recon","version":"0.1.0",
            "purpose":"Authorized, non-invasive HTTP posture checks","results":results}
    jp,hp=out/"report.json",out/"report.html"
    jp.write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    hp.write_text(render_html(report),encoding="utf-8")
    return jp,hp
