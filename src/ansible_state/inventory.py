"""Agentless host inventory using Ansible's connection and privilege model.

The collector runs only read-only shell commands. The output is JSON and is
retrieved through an Ansible callback, not through SSH access from Python.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import os

VOLATILE_SYSCTL_KEYS = frozenset((
    "fs.dentry-state", "fs.file-nr", "fs.inode-nr", "fs.inode-state",
    "kernel.ns_last_pid", "kernel.random.uuid", "kernel.random.boot_id",
    "net.netfilter.nf_conntrack_count",
))

COLLECTOR = r'''#!/usr/bin/env python3
import hashlib, json, os, pwd, re, shutil, subprocess, stat

def run(*cmd):
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=45)
        return p.stdout if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None

def packages():
    out = run("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
    if out is None:
        out = run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
    return None if out is None else dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)

def services():
    out = run("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
    if out is None: return None
    enabled = dict((p[0], p[1]) for line in out.splitlines() if len(p := line.split()) >= 2)
    active_out = run("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
    if active_out is None: return None
    active = dict((p[0], p[2]) for line in active_out.splitlines() if len(p := line.split()) >= 4)
    return {name: {"unit_file_state": state, "active_state": active.get(name, "not-loaded")} for name, state in enabled.items()}

def listeners():
    out = run("ss", "-H", "-lntup")
    if out is None: return None
    # Stable network endpoints, not process IDs or ephemeral metadata.
    result = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5:
            result.add(p[0] + " " + p[4])
    return sorted(result)

def users():
    try:
        return {u.pw_name: {"uid": u.pw_uid, "gid": u.pw_gid, "home": u.pw_dir,
                            "shell": u.pw_shell} for u in pwd.getpwall()}
    except OSError:
        return None

def cron():
    if shutil.which("crontab") is None:
        return None
    try:
        p = subprocess.run(("crontab", "-l"), text=True, capture_output=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if p.returncode == 0:
        return {"current_user": p.stdout}
    if p.returncode == 1 and "no crontab for" in p.stderr.lower():
        return {"current_user": ""}
    return None

def timers():
    out = run("systemctl", "list-unit-files", "--type=timer", "--no-legend", "--no-pager")
    if out is None: return None
    return dict((p[0], p[1]) for line in out.splitlines() if len(p := line.split()) >= 2)

# Runtime counters are not configuration and change without administrator action.
VOLATILE_SYSCTL = (
    "fs.dentry-state", "fs.file-nr", "fs.inode-nr", "fs.inode-state",
    "kernel.ns_last_pid", "kernel.random.uuid", "kernel.random.boot_id",
    "net.netfilter.nf_conntrack_count",
)
def sysctl():
    out = run("sysctl", "-a")
    if out is None: return None
    result = {}
    for line in out.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            if key not in VOLATILE_SYSCTL:
                result[key] = value
    return result

def firewall():
    if shutil.which("nft"):
        out = run("nft", "-j", "list", "ruleset")
        if out is None: return None
        try:
            ruleset = json.loads(out)
            for entry in ruleset.get("nftables", []):
                for value in entry.values():
                    if isinstance(value, dict):
                        value.pop("handle", None)
                        value.pop("packets", None)
                        value.pop("bytes", None)
            return {"nftables": ruleset}
        except (ValueError, TypeError, AttributeError):
            return None
    if shutil.which("iptables-save"):
        out = run("iptables-save", "-c")
        if out is None: return None
        return {"iptables": re.sub(r"\\[[0-9]+:[0-9]+\\]", "[0:0]", out)}
    return {}

def containers():
    if shutil.which("docker") is None:
        return {}
    out = run("docker", "ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.State}}")
    if out is None: return None
    result = {}
    for line in out.splitlines():
        p = line.split("|", 2)
        if len(p) == 3:
            result[p[0]] = {"image": p[1], "state": p[2]}
    return result

def filesystem():
    roots = ("/etc", "/usr/local/etc", "/usr/local/bin", "/opt", "/srv")
    items = {}
    for root in roots:
        if not os.path.isdir(root): continue
        try:
            root_dev = os.lstat(root).st_dev
            for base, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]
                try:
                    if os.lstat(base).st_dev != root_dev:
                        dirs[:] = []
                        continue
                except OSError:
                    dirs[:] = []
                    continue
                for name in dirs + files:
                    path = os.path.join(base, name)
                    try:
                        st = os.lstat(path)
                        if st.st_dev != root_dev: continue
                        kind = ("symlink" if stat.S_ISLNK(st.st_mode) else
                                "file" if stat.S_ISREG(st.st_mode) else
                                "directory" if stat.S_ISDIR(st.st_mode) else "other")
                        record = {"type": kind, "mode": oct(stat.S_IMODE(st.st_mode)),
                                  "uid": st.st_uid, "gid": st.st_gid}
                        if kind == "symlink": record["target"] = os.readlink(path)
                        if kind == "file" and st.st_size <= 8 * 1024 * 1024:
                            h = hashlib.sha256()
                            with open(path, "rb") as fh:
                                for chunk in iter(lambda: fh.read(131072), b""): h.update(chunk)
                            record["sha256"] = h.hexdigest()
                        elif kind == "file":
                            record["size"] = st.st_size
                        items[path] = record
                    except (OSError, PermissionError):
                        items[path] = {"type": "unreadable"}
        except OSError:
            continue
    return items

print(json.dumps({"schema": 1, "packages": packages(), "services": services(),
                  "listeners": listeners(), "users": users(), "filesystem": filesystem(),
                  "cron": cron(), "timers": timers(), "sysctl": sysctl(),
                  "firewall": firewall(), "containers": containers()},
                 sort_keys=True))
'''

def collect(host_pattern: str, ansible_args: list[str] | None = None) -> tuple[int, dict]:
    """Run a collector with ansible.builtin.script; return host -> inventory.

    The collector is copied by Ansible to the target and removed afterwards.
    """
    args = ansible_args or []
    with tempfile.TemporaryDirectory(prefix="ansible-state-inventory-") as tmp:
        root = Path(tmp)
        script = root / "collector.py"
        script.write_text(COLLECTOR, encoding="utf-8")
        playbook = root / "collect.json"
        playbook.write_text(json.dumps([{
            "name": "Read-only system inventory",
            "hosts": host_pattern,
            "gather_facts": False,
            "tasks": [{
                "name": "ansible-state inventory",
                "ansible.builtin.script": str(script),
                "changed_when": False,
            }],
        }]), encoding="utf-8")
        events = root / "events.jsonl"
        env = os.environ.copy()
        plugin_dir = Path(__file__).resolve().parent / "callback_plugins"
        current = env.get("ANSIBLE_CALLBACK_PLUGINS", "")
        env["ANSIBLE_CALLBACK_PLUGINS"] = os.pathsep.join(
            p for p in (str(plugin_dir), current) if p
        )
        enabled = env.get("ANSIBLE_CALLBACKS_ENABLED", "")
        env["ANSIBLE_CALLBACKS_ENABLED"] = ",".join(
            p for p in (enabled, "state_events") if p
        )
        env["ANSIBLE_STATE_EVENTS"] = str(events)
        env["ANSIBLE_STATE_INVENTORY"] = "1"
        try:
            status = subprocess.call(["ansible-playbook", *args, str(playbook)], env=env)
        except FileNotFoundError:
            return 127, {}
        collected = {}
        if events.exists():
            for line in events.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                    if event.get("status") == "ok" and event.get("inventory"):
                        collected[event["host"]] = json.loads(event["inventory"])
                except (ValueError, KeyError, TypeError):
                    continue
        if not collected:
            return status or 2, {}
        return status, collected
