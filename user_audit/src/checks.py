from __future__ import annotations
import os
import pwd
from pathlib import Path
from typing import Dict, List, Any
from .utils import run_cmd, read_file_safe, exists_user

# NOTE: these functions are best-effort and must not change system state.

def get_passwd_info(username: str) -> Dict[str, Any]:
    try:
        u = pwd.getpwnam(username)
        return {
            "username": u.pw_name,
            "uid": u.pw_uid,
            "gid": u.pw_gid,
            "home": u.pw_dir,
            "shell": u.pw_shell,
        }
    except KeyError:
        return {}

def last_logins(username: str, limit: int = 10) -> List[str]:
    rc, out, err = run_cmd(f"last -n {limit} {username}", timeout=3)
    if rc == 0 and out:
        return out.splitlines()
    # fallback to lastlog
    rc, out, err = run_cmd(f"lastlog -u {username}", timeout=3)
    return out.splitlines() if out else []

def check_cron(username: str) -> Dict[str, Any]:
    found = []
    # per-user crontab
    rc, out, err = run_cmd(f"crontab -l -u {username}", timeout=3)
    if rc == 0 and out:
        found.append({"source": "crontab", "content": out})
    # system cron dirs
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/var/spool/cron/crontabs"]
    for d in cron_dirs:
        try:
            for p in Path(d).glob("*"):
                if p.is_file():
                    text = read_file_safe(str(p))
                    if username in text or p.name == username:
                        found.append({"source": str(p), "content": text})
        except Exception:
            continue
    return {"crons": found}

def check_ssh(username: str) -> Dict[str, Any]:
    info = get_passwd_info(username)
    home = info.get("home")
    found = {}
    if not home:
        return {"ssh": found}
    sshdir = Path(home) / ".ssh"
    auth = sshdir / "authorized_keys"
    if sshdir.exists():
        found["sshdir_exists"] = True
        try:
            st = sshdir.stat()
            found["sshdir_mode"] = oct(st.st_mode & 0o777)
        except Exception:
            pass
    if auth.exists():
        found["authorized_keys"] = read_file_safe(str(auth))
        try:
            st = auth.stat()
            found["authorized_keys_mode"] = oct(st.st_mode & 0o777)
            found["authorized_keys_writable"] = bool(st.st_mode & 0o222)
        except Exception:
            pass
    # also check .ssh for other files
    if sshdir.exists():
        other = []
        for p in sshdir.iterdir():
            if p.is_file() and p.name != "authorized_keys":
                other.append(p.name)
        if other:
            found["other_ssh_files"] = other
    return {"ssh": found}

def check_processes(username: str) -> Dict[str, Any]:
    rc, out, err = run_cmd(f"ps -u {username} -o pid,ppid,cmd,%cpu,%mem --no-headers", timeout=5)
    procs = out.splitlines() if out else []
    # check network connections of user's processes via ss
    rc2, ss_out, ss_err = run_cmd("ss -tunap", timeout=5)
    conns = []
    if ss_out:
        # naive filter: lines containing 'users:' or 'pid='
        for line in ss_out.splitlines():
            if f"users:((" in line or "pid=" in line:
                if username in line or f"{username}?" in line:
                    conns.append(line.strip())
                else:
                    # attempt to extract pid= and map to username via /proc/<pid>/status
                    import re
                    m = re.search(r"pid=(\d+),", line)
                    if m:
                        pid = m.group(1)
                        try:
                            with open(f"/proc/{pid}/status","r",errors="ignore") as fh:
                                text = fh.read()
                                if f"Uid:" in text:
                                    # check real uid
                                    for l in text.splitlines():
                                        if l.startswith("Uid:"):
                                            parts=l.split()
                                            # parts[1] is uid
                                            from pwd import getpwuid
                                            try:
                                                u = getpwuid(int(parts[1])).pw_name
                                                if u == username:
                                                    conns.append(line.strip())
                                            except Exception:
                                                pass
                        except Exception:
                            pass
    return {"processes": procs, "network_connections": conns}

def check_shell_history(username: str) -> Dict[str, Any]:
    info = get_passwd_info(username)
    home = info.get("home")
    result = {}
    if not home:
        return {"history": result}
    candidates = [".bash_history", ".zsh_history", ".ash_history", ".config/xfce4/terminal/*history", ".local/share/recently-used.xbel"]
    histories = {}
    for c in candidates:
        path = Path(home) / c
        if "*" in c:
            import glob
            for p in Path(home).glob(c):
                if p.exists():
                    histories[str(p)] = read_file_safe(str(p))
        else:
            if path.exists():
                histories[str(path)] = read_file_safe(str(path))
    return {"history": histories}

def check_auth_logs(username: str, lines: int = 200) -> Dict[str, Any]:
    results = []
    # try journalctl first (if systemd)
    rc, out, err = run_cmd(f"journalctl -u ssh -n {lines} --no-pager", timeout=4)
    if rc == 0 and out:
        results.append({"source":"journalctl:ssh","content": out})
    # look in /var/log for auth logs
    candidates = ["/var/log/auth.log", "/var/log/secure"]
    for p in candidates:
        if os.path.exists(p):
            text = read_file_safe(p)
            # naive filter for username
            filtered = "\n".join([l for l in text.splitlines() if username in l or "Failed password" in l or "Accepted password" in l])
            if filtered:
                results.append({"source": p, "content": filtered[-5000:]})
    return {"auth": results}

def check_setuid_and_world_writable(username: str, max_find=2000) -> Dict[str, Any]:
    info = get_passwd_info(username)
    home = info.get("home")
    found = {"setuid": [], "world_writable": []}
    if not home:
        return found
    count = 0
    for root, dirs, files in os.walk(home):
        for fname in files:
            try:
                path = os.path.join(root,fname)
                st = os.lstat(path)
                mode = st.st_mode
                # setuid bit
                if mode & 0o4000:
                    found["setuid"].append(path)
                if mode & 0o002:
                    found["world_writable"].append(path)
            except Exception:
                pass
            count += 1
            if count > max_find:
                return found
    return found

def check_systemd_user_units(username: str) -> Dict[str, Any]:
    # best-effort: try sudo -u <user> systemctl --user list-units --no-pager
    rc, out, err = run_cmd(f"sudo -n -u {username} systemctl --user list-units --no-pager", timeout=4)
    if rc == 0 and out:
        return {"systemd_user": out.splitlines()}
    return {"systemd_user": []}
