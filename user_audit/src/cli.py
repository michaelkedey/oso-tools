#!/usr/bin/env python3
from __future__ import annotations
import argparse, os, sys
from . import __version__
from .audit import audit_one_user, audit_all_users
from .output import print_banner, print_full_report, save_json
from .output import print_user_summary
from rich.console import Console
from typing import Optional

console = Console()

def parse_args():
    p = argparse.ArgumentParser(prog="user-audit", description="Extended user auditing tool")
    p.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--user", help="Username to audit (single user)")
    group.add_argument("--all", action="store_true", help="Audit all users")
    p.add_argument("--deep", action="store_true", help="Deep checks (may be slow)")
    p.add_argument("--json", action="store_true", help="Output JSON to stdout")
    p.add_argument("--output", type=str, help="Save full JSON report to file")
    p.add_argument("--suspicious-file", type=str, help="Save suspicious-only summary to file")
    return p.parse_args()

def gather_suspicious(report: dict) -> list:
    """Return list of suspicious findings for a single user report."""
    sus = []
    p = report.get("passwd", {})
    username = p.get("username","?")
    # 1. writable authorized_keys
    ssh = report.get("ssh",{})
    if ssh.get("authorized_keys_writable"):
        sus.append(f"{username}: authorized_keys is writable (permissions {ssh.get('authorized_keys_mode')})")
    ak = ssh.get("authorized_keys")
    if ak:
        # count keys
        count = len([l for l in ak.splitlines() if l.strip() and not l.strip().startswith("#")])
        if count > 5:
            sus.append(f"{username}: authorized_keys contains {count} keys (>=5)")
        # presence of suspicious patterns
        if "ssh-rsa" not in ak and "ssh-ed25519" not in ak and "ecdsa-" not in ak:
            sus.append(f"{username}: authorized_keys content lacks usual key markers")
    # cron entries with fetchers or reverse shells
    for c in report.get("crons", []):
        t = c.get("content","")
        if any(x in t for x in ["curl ", "wget ", "nc ", "netcat", "bash -i", "python -c", "perl -e"]):
            sus.append(f"{username}: cron file {c.get('source')} contains potential downloader/reverse shell usage")
    # processes with network connections
    n = report.get("network_connections", []) or []
    if n:
        sus.append(f"{username}: has {len(n)} network socket(s) associated with processes (possible beacon/connection)")
    # shell history suspicious commands
    hist = report.get("history", {}) or {}
    suspicious_cmds = ["nc ", "netcat", "curl ", "wget ", "python -c", "bash -i", "perl -e", "openssl s_client"]
    for path, content in hist.items():
        text = content.lower()
        for s in suspicious_cmds:
            if s in text:
                sus.append(f"{username}: suspicious command '{s.strip()}' found in history {path}")
                break
    # setuid/world-writable
    fc = report.get("file_checks", {}) or {}
    if (fc.get("setuid") or []):
        sus.append(f"{username}: found setuid files in home ({len(fc.get('setuid'))})")
    if (fc.get("world_writable") or []):
        sus.append(f"{username}: found world-writable files in home ({len(fc.get('world_writable'))})")
    # auth logs: many failed attempts / accepted logins from remote
    auths = report.get("auth",[]) or []
    for a in auths:
        cont = a.get("content","").lower()
        if "failed password" in cont or "invalid user" in cont:
            sus.append(f"{username}: auth logs contain failures or invalid-user lines ({a.get('source')})")
        if "accepted password" in cont or "accepted publickey" in cont:
            sus.append(f"{username}: auth logs show successful authentication lines ({a.get('source')})")
    return sus

def main():
    args = parse_args()
    if not args.no_banner:
        print_banner("USER-AUDIT", __version__)
    if args.user:
        if not args.user:
            console.print("[red]No user provided[/red]")
            sys.exit(2)
        report = audit_one_user(args.user, deep=args.deep)
        # print short summary & full report
        print_user_summary(report.get("passwd") and report or {"passwd": {"username": args.user}})
        print_full_report(report, args.user)
        sus = gather_suspicious(report)
        if sus:
            console.print("\n[bold red]Suspicious findings:[/bold red]")
            for s in sus:
                console.print(f" - {s}")
        else:
            console.print("\n[green]No immediate suspicious findings detected.[/green]")
        if args.json:
            import json
            console.print_json(data=report)
        if args.output:
            save_json(report, args.output)
        if args.suspicious_file:
            Path(args.suspicious_file).write_text("\n".join(sus or ["No suspicious findings"]))
    elif args.all:
        reports = audit_all_users(deep=args.deep)
        # print a small table of usernames and a quick flag count
        from rich.table import Table
        table = Table(title="User Audit Summary")
        table.add_column("User")
        table.add_column("Suspicious")
        table.add_column("Has SSH")
        table.add_column("Procs")
        for item in reports:
            u = item["username"]
            r = item["report"]
            sus = gather_suspicious(r)
            ssh_present = bool((r.get("ssh") or {}).get("authorized_keys"))
            procs = len(r.get("processes") or [])
            table.add_row(u, str(len(sus)), "yes" if ssh_present else "no", str(procs))
        console.print(table)
        if args.json:
            import json
            console.print_json(data=reports)
        if args.output:
            save_json(reports, args.output)
        if args.suspicious_file:
            # aggregate
            lines = []
            for item in reports:
                u = item["username"]
                sus = gather_suspicious(item["report"])
                if sus:
                    lines.append(f"== {u} ==")
                    lines.extend(sus)
            Path(args.suspicious_file).write_text("\n".join(lines or ["No suspicious findings across users"]))
    else:
        console.print("[red]No action chosen. Use --user or --all[/red]")

if __name__ == "__main__":
    main()
