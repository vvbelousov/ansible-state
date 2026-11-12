"""Agentless host inventory using Ansible's connection and privilege model.

The collector runs only read-only shell commands. The output is JSON and is
retrieved through an Ansible callback, not through SSH access from Python.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

VOLATILE_SYSCTL_KEYS = frozenset((
    "fs.quota.syncs", "fs.dentry-state", "fs.file-nr", "fs.inode-nr", "fs.inode-state",
    "kernel.ns_last_pid", "kernel.random.uuid", "kernel.random.boot_id",
    "net.netfilter.nf_conntrack_count", "kernel.pty.nr",
))

COLLECTOR = r'''#!/usr/bin/env python3
import hashlib, json, os, pwd, re, shutil, subprocess, stat
from datetime import datetime, timezone

COLLECTION = {}
COLLECTION_ERRORS = {}
DOMAIN = None

def failure(error, resource=None, command=None, returncode=None):
    detail = {"error": str(error)[:300]}
    if resource is not None: detail["resource"] = resource
    if command is not None: detail["command"] = command
    if returncode is not None: detail["returncode"] = returncode
    COLLECTION[DOMAIN]["complete"] = False
    COLLECTION[DOMAIN].setdefault("errors", []).append(detail)

def run(*cmd):
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=45)
        if p.returncode == 0: return p.stdout
        failure(p.stderr, command=cmd[0], returncode=p.returncode)
    except (OSError, subprocess.TimeoutExpired) as exc:
        failure(exc, command=cmd[0])
    return None

def packages():
    out = run("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
    if out is None:
        out = run("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
    if out is not None:
        COLLECTION[DOMAIN]["complete"] = True
        COLLECTION[DOMAIN].pop("errors", None)
    return None if out is None else dict(line.split("\t", 1) for line in out.splitlines() if "\t" in line)

def services():
    out = run("systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager")
    if out is None: return None
    enabled = dict((p[0], p[1]) for line in out.splitlines() if len(p := line.split()) >= 2)
    active_out = run("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager")
    if active_out is None:
        return {name: {"unit_file_state": state} for name, state in enabled.items()}
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
    except OSError as exc:
        failure(exc)
        return None

def cron():
    try:
        owner = pwd.getpwuid(os.geteuid()).pw_name
    except KeyError:
        failure("effective UID has no account name")
        return None
    COLLECTION[DOMAIN]["scope"] = {"owner": owner}
    if shutil.which("crontab") is None:
        failure("crontab executable unavailable")
        return None
    try:
        p = subprocess.run(("crontab", "-l"), text=True, capture_output=True, timeout=45,
                           env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        failure(exc, command="crontab")
        return None
    if p.returncode == 0:
        return {owner: p.stdout}
    if p.returncode == 1 and re.fullmatch(r"(?:crontab: )?no crontab for " + re.escape(owner),
                                         p.stderr.strip(), re.IGNORECASE):
        return {owner: ""}
    failure(p.stderr, command="crontab", returncode=p.returncode)
    return None

def timers():
    out = run("systemctl", "list-unit-files", "--type=timer", "--no-legend", "--no-pager")
    if out is None: return None
    return dict((p[0], p[1]) for line in out.splitlines() if len(p := line.split()) >= 2)

# Runtime counters are not configuration and change without administrator action.
VOLATILE_SYSCTL = (
    "fs.quota.syncs", "fs.dentry-state", "fs.file-nr", "fs.inode-nr", "fs.inode-state",
    "kernel.ns_last_pid", "kernel.random.uuid", "kernel.random.boot_id",
    "net.netfilter.nf_conntrack_count", "kernel.pty.nr",
)
def sysctl():
    try:
        proc = subprocess.run(("sysctl", "-a"), text=True, capture_output=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        failure(exc, command="sysctl")
        return None
    if proc.returncode or proc.stderr.strip():
        failure(proc.stderr, command="sysctl", returncode=proc.returncode)
    # Some kernels expose unreadable /proc/sys entries; sysctl may exit nonzero
    # while still returning a useful inventory on stdout.
    out = proc.stdout
    result = {}
    for line in out.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            if key not in VOLATILE_SYSCTL:
                result[key] = value
    return result if result or proc.returncode == 0 else None

def firewall_command(*cmd):
    return run(*cmd)

def firewall():
    if shutil.which("nft"):
        out = firewall_command("nft", "-j", "list", "ruleset")
        if out is None: return None
        try:
            ruleset = json.loads(out)
            if not isinstance(ruleset, dict) or not isinstance(ruleset.get("nftables"), list):
                raise ValueError("invalid nftables ruleset")
            def stable(value):
                if isinstance(value, dict):
                    return {k: stable(v) for k, v in value.items()
                            if k not in ("handle", "packets", "bytes")}
                if isinstance(value, list):
                    return [stable(v) for v in value if not isinstance(v, dict) or "metainfo" not in v]
                return value
            ruleset = stable(ruleset)
            return {"nftables": ruleset}
        except (ValueError, TypeError, AttributeError):
            failure("invalid JSON ruleset", command="nft")
            return None
    if shutil.which("iptables-save"):
        out = firewall_command("iptables-save", "-c")
        if out is None: return None
        # iptables-save headers contain timestamps; counters are runtime only.
        out = "\n".join(line for line in out.splitlines() if not line.startswith("#"))
        return {"iptables": re.sub(r"\[[0-9]+:[0-9]+\]", "[0:0]", out)}
    failure("no supported firewall executable")
    return None

def containers():
    COLLECTION[DOMAIN]["scope"]["endpoint"] = os.environ.get("DOCKER_HOST", "default")
    COLLECTION[DOMAIN]["scope"]["context"] = os.environ.get("DOCKER_CONTEXT", "default")
    if shutil.which("docker") is None:
        failure("docker executable unavailable")
        return None
    out = run("docker", "ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.State}}")
    if out is None: return None
    result = {}
    for line in out.splitlines():
        p = line.split("|", 2)
        if len(p) == 3:
            result[p[0]] = {"image": p[1], "state": p[2]}
        else:
            failure("invalid docker output", command="docker")
    return result

def filesystem():
    roots = ("/etc", "/usr/local/etc", "/usr/local/bin", "/opt", "/srv")
    items = {}
    COLLECTION[DOMAIN]["scope"].update({"roots": list(roots), "excluded_mounts": []})
    excluded = COLLECTION[DOMAIN]["scope"]["excluded_mounts"]
    for root in roots:
        try:
            os.lstat(root)
        except FileNotFoundError:
            continue
        except OSError as exc:
            failure(exc, resource=root)
            continue
        try:
            if stat.S_ISLNK(os.lstat(root).st_mode):
                excluded.append(root)
                continue
            root_dev = os.lstat(root).st_dev
            for base, dirs, files in os.walk(root, followlinks=False,
                                              onerror=lambda exc: failure(exc, resource=exc.filename)):
                try:
                    if os.lstat(base).st_dev != root_dev:
                        excluded.append(base)
                        dirs[:] = []
                        continue
                except OSError as exc:
                    failure(exc, resource=base)
                    dirs[:] = []
                    continue
                for name in dirs + files:
                    path = os.path.join(base, name)
                    try:
                        st = os.lstat(path)
                        if st.st_dev != root_dev:
                            excluded.append(path)
                            continue
                        kind = ("symlink" if stat.S_ISLNK(st.st_mode) else
                                "file" if stat.S_ISREG(st.st_mode) else
                                "directory" if stat.S_ISDIR(st.st_mode) else "other")
                        record = {"type": kind, "mode": oct(stat.S_IMODE(st.st_mode)),
                                  "uid": st.st_uid, "gid": st.st_gid}
                        items[path] = record
                        if kind == "symlink": record["target"] = os.readlink(path)
                        if kind == "file" and st.st_size <= 8 * 1024 * 1024:
                            h = hashlib.sha256()
                            with open(path, "rb") as fh:
                                for chunk in iter(lambda: fh.read(131072), b""): h.update(chunk)
                            record["sha256"] = h.hexdigest()
                        elif kind == "file":
                            record["size"] = st.st_size
                        items[path] = record
                    except OSError as exc:
                        failure(exc, resource=path)
                        items.setdefault(path, {"type": "unreadable"})
        except OSError as exc:
            failure(exc, resource=root)
    excluded[:] = sorted(set(excluded))
    return items

def collect_inventory():
    global DOMAIN
    result = {"schema": 2, "_collected_at": datetime.now(timezone.utc).isoformat()}
    for name, function in (("packages", packages), ("services", services),
                           ("listeners", listeners), ("users", users),
                           ("filesystem", filesystem), ("cron", cron),
                           ("timers", timers), ("sysctl", sysctl),
                           ("firewall", firewall), ("containers", containers)):
        DOMAIN = name
        scope = {"uid": os.geteuid()} if name in ("filesystem", "sysctl", "firewall", "containers") else {"system": True}
        COLLECTION[name] = {"scope": scope, "complete": True}
        result[name] = function()
        if result[name] is None:
            failure("domain unavailable")
        if COLLECTION[name].get("errors"):
            COLLECTION_ERRORS[name] = COLLECTION[name]["errors"]
    result["_collection"] = COLLECTION
    result["_collection_errors"] = COLLECTION_ERRORS
    return result

if __name__ == "__main__":
    print(json.dumps(collect_inventory(), sort_keys=True))
'''

def collect(host_pattern: str, ansible_args: list[str] | None = None,
            fallback_hosts: list[str] | None = None) -> tuple[int, dict]:
    """Return (status, host -> inventory): 0 complete, 3 partial, 2 failed, 127 missing.

    The collector is copied by Ansible to the target and removed afterwards.
    """
    args = list(ansible_args or [])
    collector_become = "--collector-become" in args
    args = [arg for arg in args if arg != "--collector-become"]
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
                "become": collector_become,
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
        def read_events():
            records = {}
            if events.exists():
                for line in events.read_text(encoding="utf-8").splitlines():
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict) and isinstance(event.get("host"), str):
                            records[event["host"]] = event
                    except (ValueError, TypeError):
                        continue
            return records

        def inventories(records):
            result = {}
            for host, event in records.items():
                try:
                    data = json.loads(event.get("inventory", ""))
                    if event.get("status") == "ok" and isinstance(data, dict) and data:
                        result[host] = data
                except (ValueError, TypeError):
                    continue
            return result

        records = read_events()
        collected = inventories(records)
        retry = [host for host, event in records.items()
                 if collector_become and (fallback_hosts is None or host in fallback_hosts) and
                 event.get("status") == "failed" and
                 any(marker in event.get("error", "").lower() for marker in
                     ("sudo", "become", "privilege escalation", "su:", "password is required"))]
        if retry:
            # Target only privilege failures; unreachable hosts are never retried.
            play = json.loads(playbook.read_text(encoding="utf-8"))
            play[0]["hosts"] = retry
            play[0]["tasks"][0]["become"] = False
            playbook.write_text(json.dumps(play), encoding="utf-8")
            events.unlink(missing_ok=True)
            fallback_status = subprocess.call(["ansible-playbook", *args, str(playbook)], env=env)
            fallback = read_events()
            recovered = inventories(fallback)
            collected.update(recovered)
            for host in retry:
                if host in recovered:
                    records[host] = fallback[host]
            # Unknown invocation errors must survive even if some hosts recovered.
            status = (fallback_status or (status if status not in (0, 2) else 0)
                      if set(retry) <= recovered.keys() else (fallback_status or 2))
            if any(event.get("status") != "ok" for event in records.values()):
                status = status or 2
        failures = (set(fallback_hosts or []) | set(records)) - collected.keys()
        if not collected:
            return 2, {}
        if status and not failures:
            for data in collected.values():
                data["_execution_error"] = {"returncode": status}
        from ansible_state.baseline import DOMAINS, domain_metadata
        incomplete = any(domain_metadata(data, domain).get("complete") is False
                         for data in collected.values() for domain in DOMAINS)
        return (3 if failures or status or incomplete else 0), collected
