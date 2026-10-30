import argparse, sys, time
from . import __version__
from .scope import ScopeError, load_scope, load_targets
from .checks import check_target
from .report import write_reports

def build_parser():
    p=argparse.ArgumentParser(prog="grevora-recon",description="Scope-limited, non-invasive HTTP posture checks.")
    p.add_argument("--version",action="version",version=f"%(prog)s {__version__}")
    p.add_argument("--scope",required=True,help="JSON authorization scope file.")
    p.add_argument("--targets",required=True,help="Text file of authorized URLs/hostnames.")
    p.add_argument("--output",default="grevora-recon-report",help="Output directory.")
    p.add_argument("--timeout",type=float,default=8.0,help="Timeout in seconds (1–20).")
    p.add_argument("--delay",type=float,default=1.0,help="Delay between targets (0–30 seconds).")
    return p

def main(argv=None):
    p=build_parser(); a=p.parse_args(argv)
    if not 1 <= a.timeout <= 20: p.error("--timeout must be between 1 and 20 seconds.")
    if not 0 <= a.delay <= 30: p.error("--delay must be between 0 and 30 seconds.")
    try: scope=load_scope(a.scope); targets=load_targets(a.targets,scope)
    except ScopeError as exc:
        print(f"Scope error: {exc}",file=sys.stderr); return 2
    print(f"GREVORA Recon {__version__} — {len(targets)} in-scope target(s)")
    results=[]
    for i,target in enumerate(targets):
        print(f"[{i+1}/{len(targets)}] Checking {target}")
        results.append(check_target(target,timeout=a.timeout))
        if i+1<len(targets) and a.delay: time.sleep(a.delay)
    jp,hp=write_reports(results,a.output)
    print(f"JSON report: {jp}"); print(f"HTML report: {hp}")
    errors=sum(r["status"]!="ok" for r in results)
    print(f"Finished: {len(results)-errors} checked, {errors} request error(s).")
    return 0 if errors==0 else 1

if __name__=="__main__": raise SystemExit(main())
