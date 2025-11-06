from __future__ import annotations
from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
import json
from pathlib import Path

console = Console()

def print_banner(appname: str, version: str):
    from pyfiglet import Figlet
    f = Figlet(font="slant")
    console.print(Panel(f.renderText(appname), subtitle=f"v{version}"))

def print_user_summary(report: Dict[str, Any]):
    passwd = report.get("passwd", {})
    username = passwd.get("username") or "?"
    table = Table(title=f"User: {username}", show_lines=False)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("UID", str(passwd.get("uid","-")))
    table.add_row("GID", str(passwd.get("gid","-")))
    table.add_row("Home", passwd.get("home","-"))
    table.add_row("Shell", passwd.get("shell","-"))
    # last login
    last = report.get("last") or []
    table.add_row("Last logins (tail)", "\n".join(last[:5]) or "-")
    # processes count
    procs = report.get("processes") or []
    table.add_row("Running processes", str(len(procs)))
    # ssh keys presence
    ssh = report.get("ssh") or {}
    table.add_row("SSH keys", "yes" if ssh.get("authorized_keys") else "no")
    console.print(table)

def print_full_report(report: Dict[str, Any], username: str):
    print_user_summary(report)
    console.print(Panel("Cron entries", title="Crons"))
    for c in report.get("crons", []):
        console.print(Panel(c.get("content","-")[:2000], title=c.get("source","cron")))

    console.print(Panel("SSH files", title="SSH"))
    ssh = report.get("ssh", {})
    if ssh:
        ak = ssh.get("authorized_keys")
        if ak:
            console.print(Markdown("**authorized_keys (head)**"))
            console.print(Panel(ak[:2000]))
        else:
            console.print("No authorized_keys found.")

    console.print(Panel("Processes (head)", title="Processes"))
    procs = report.get("processes", []) or []
    console.print(Panel("\n".join(procs[:50]) or "-", title="ps -u"))

    console.print(Panel("Network connections (head)", title="Network"))
    n = report.get("network_connections", [])
    console.print(Panel("\n".join(n[:50]) or "-"))

    console.print(Panel("Shell histories (head)", title="History"))
    histories = report.get("history", {}) or {}
    for path, content in histories.items():
        console.print(Panel(f"[bold]{path}[/bold]\n" + (content[-2000:] if content else "-")))

    console.print(Panel("Auth logs (head)", title="Auth"))
    auths = report.get("auth", []) or []
    for a in auths:
        console.print(Panel(a.get("content","")[-2000:] or "-", title=a.get("source","auth")))

    # file checks
    fc = report.get("file_checks", {})
    console.print(Panel("Setuid files (head)", title="Setuid"))
    for p in (fc.get("setuid") or [])[:30]:
        console.print(p)
    console.print(Panel("World-writable files (head)", title="WW"))
    for p in (fc.get("world_writable") or [])[:30]:
        console.print(p)

def save_json(report: Any, path: str):
    p = Path(path)
    p.write_text(json.dumps(report, indent=2))
