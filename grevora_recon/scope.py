import ipaddress, json, re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MAX_TARGETS = 100
FORBIDDEN = {"localhost", "localhost.localdomain", "metadata.google.internal"}
HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$")

class ScopeError(ValueError): pass

def _root(root):
    root = root.strip().lower().rstrip(".")
    if not root or "/" in root or ":" in root or "@" in root or root in FORBIDDEN:
        raise ScopeError(f"Invalid or forbidden scope domain: {root!r}")
    try: ipaddress.ip_address(root)
    except ValueError: pass
    else: raise ScopeError("IP-address scopes are not accepted; use an authorized DNS domain.")
    if "." not in root or not HOST_RE.fullmatch(root):
        raise ScopeError(f"Scope entry must be a fully-qualified domain: {root!r}")
    return root

def load_scope(path):
    try: data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc: raise ScopeError(f"Could not read scope JSON: {exc}") from exc
    roots = data.get("authorized_domains") if isinstance(data, dict) else None
    if not isinstance(roots, list) or not roots: raise ScopeError("Scope JSON needs a non-empty authorized_domains array.")
    return sorted(set(_root(str(x)) for x in roots))

def normalize_target(raw, authorized_domains):
    raw = raw.strip()
    if not raw or raw.startswith("#"): raise ScopeError("Empty or comment target.")
    try:
        parsed = urlsplit(raw if "://" in raw else "https://" + raw)
        port = parsed.port
    except ValueError as exc: raise ScopeError(f"Malformed target URL: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"}: raise ScopeError("Only HTTP and HTTPS are supported.")
    if parsed.username is not None or parsed.password is not None: raise ScopeError("Credentials in URLs are not allowed.")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host in FORBIDDEN: raise ScopeError("Missing or forbidden hostname.")
    try: ipaddress.ip_address(host)
    except ValueError: pass
    else: raise ScopeError("IP-address targets are blocked; use an authorized DNS hostname.")
    if "." not in host or not HOST_RE.fullmatch(host): raise ScopeError("Target must be a fully-qualified DNS hostname.")
    roots = [_root(x) for x in authorized_domains]
    if not any(host == root or host.endswith("." + root) for root in roots):
        raise ScopeError(f"Out-of-scope host rejected: {host}")
    return urlunsplit((parsed.scheme.lower(), host + (f":{port}" if port else ""), parsed.path or "/", parsed.query, ""))

def load_targets(path, authorized_domains):
    try: lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc: raise ScopeError(f"Could not read targets file: {exc}") from exc
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"): continue
        targets.append(normalize_target(line, authorized_domains))
        if len(targets) > MAX_TARGETS: raise ScopeError(f"Maximum {MAX_TARGETS} targets per run.")
    if not targets: raise ScopeError("No targets found.")
    return list(dict.fromkeys(targets))
