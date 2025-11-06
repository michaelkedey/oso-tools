from __future__ import annotations
from typing import List, Dict, Any, Optional
from .checks import (
    get_passwd_info, last_logins, check_cron, check_ssh, check_processes,
    check_shell_history, check_auth_logs, check_setuid_and_world_writable,
    check_systemd_user_units
)
import pwd

def audit_one_user(username: str, deep: bool = False) -> Dict[str, Any]:
    if not username:
        return {}
    out = {}
    out["passwd"] = get_passwd_info(username)
    out["last"] = last_logins(username, limit=10)
    out.update(check_cron(username))
    out.update(check_ssh(username))
    out.update(check_processes(username))
    out.update(check_shell_history(username))
    out.update(check_auth_logs(username))
    out.update({"file_checks": check_setuid_and_world_writable(username)})
    out.update(check_systemd_user_units(username))
    # Optionally add more deep checks (file owners across filesystem) if deep=True
    return out

def audit_all_users(deep: bool = False) -> List[Dict[str, Any]]:
    users = [p.pw_name for p in pwd.getpwall() if int(p.pw_uid) >= 0]
    results = []
    for u in users:
        results.append({"username": u, "report": audit_one_user(u, deep=deep)})
    return results
