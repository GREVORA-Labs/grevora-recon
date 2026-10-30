import ipaddress, socket, time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPHandler, HTTPSHandler
from urllib.parse import urlsplit
from html import escape

SECURITY_HEADERS = {
 "strict-transport-security": "HSTS helps browsers require HTTPS.",
 "content-security-policy": "CSP can reduce the impact of some injection attacks.",
 "x-content-type-options": "nosniff helps prevent MIME-type sniffing.",
 "referrer-policy": "Controls referrer information sent to other sites.",
 "permissions-policy": "Controls access to selected browser features."
}
DISCLOSURE_HEADERS = ("server", "x-powered-by")

class NoRedirect:
    def http_error_301(self, req, fp, code, msg, headers): return fp
    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301

def public_dns_only(host):
    try: answers = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc: raise OSError(f"DNS resolution failed: {exc}") from exc
    if not answers: raise OSError("DNS returned no addresses.")
    for value in {a[4][0].split("%", 1)[0] for a in answers}:
        ip = ipaddress.ip_address(value)
        if not ip.is_global: raise OSError(f"Non-public IP resolution blocked: {ip}")

def check_target(url, timeout=8.0, user_agent="GREVORA-Recon/0.1 (+authorized posture checks)"):
    host = urlsplit(url).hostname
    result = {"target":url,"status":"error","http_status":None,"final_url":None,
              "elapsed_ms":None,"headers":{},"findings":[],"error":None}
    start = time.monotonic()
    response = None
    try:
        if not host: raise ValueError("Target has no hostname.")
        public_dns_only(host)
        opener = build_opener(NoRedirect(), HTTPHandler(), HTTPSHandler())
        req = Request(url, method="HEAD", headers={"User-Agent":user_agent,"Accept":"*/*"})
        try: response = opener.open(req, timeout=timeout)
        except HTTPError as exc:
            if exc.code in {400,403,405,501}:
                exc.close()
                req = Request(url, method="GET", headers={"User-Agent":user_agent,"Accept":"*/*","Range":"bytes=0-0"})
                response = opener.open(req, timeout=timeout)
            else: response = exc
        status = getattr(response,"status",None) or getattr(response,"code",None)
        result["http_status"], result["final_url"] = status, url
        headers = {k.lower():v.strip() for k,v in response.headers.items()}
        result["headers"] = {k:headers[k] for k in sorted(headers) if k in SECURITY_HEADERS or k in DISCLOSURE_HEADERS or k=="location"}
        if status and 300 <= status < 400 and "location" in headers:
            result["findings"].append({"severity":"info","id":"REDIRECT_NOT_FOLLOWED","message":"Redirect returned; not followed.","evidence":{"location":headers["location"]}})
        for name, note in SECURITY_HEADERS.items():
            if name not in headers:
                result["findings"].append({"severity":"low","id":"MISSING_"+name.upper().replace("-","_"),
                    "message":f"Missing response header: {name}. {note}","evidence":{"header":name,"present":False}})
        for name in DISCLOSURE_HEADERS:
            if name in headers:
                result["findings"].append({"severity":"info","id":"SERVER_HEADER_PRESENT",
                    "message":f"Technology disclosure header present: {name}. Review whether needed.",
                    "evidence":{"header":name,"value":headers[name]}})
        result["status"] = "ok"
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        result["error"] = str(getattr(exc,"reason",exc))
        result["findings"].append({"severity":"info","id":"REQUEST_FAILED",
            "message":"Target could not be checked; this is not proof of a vulnerability.",
            "evidence":{"error":result["error"]}})
    finally:
        if response is not None:
            try: response.close()
            except Exception: pass
        result["elapsed_ms"] = round((time.monotonic()-start)*1000,2)
    return result

def render_html(report):
    rows=[]
    for item in report.get("results",[]):
        findings=[]
        for f in item.get("findings",[]):
            findings.append("<li><strong>"+escape(str(f.get("severity","")))+" — "+escape(str(f.get("id","")))+
                "</strong>: "+escape(str(f.get("message","")))+" <code>"+escape(str(f.get("evidence",{})))+"</code></li>")
        rows.append("<section><h2>"+escape(str(item.get("target","")))+"</h2><p>Status: "+
            escape(str(item.get("http_status","unavailable")))+" | Check: "+escape(str(item.get("status","")))+
            "</p><ul>"+"".join(findings)+"</ul></section>")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GREVORA Recon Report</title><style>body{font:16px/1.5 system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#202124}
header{border-bottom:2px solid #b38b35;padding-bottom:1rem}section{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
code{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body><header><h1>GREVORA Recon</h1>
<p>Authorized, non-invasive HTTP posture checks</p><small>Findings require human validation.</small></header>"""+"".join(rows)+"</body></html>"
