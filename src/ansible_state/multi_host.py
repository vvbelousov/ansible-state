"""Explicit multi-host baseline review and approval."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

from ansible_state.baseline import BaselineStore, diff


def resolve_hosts(pattern: str, ansible_args: list[str]) -> list[str]:
    """Use Ansible's own inventory and host-pattern resolution."""
    cmd = ["ansible", pattern, "--list-hosts", *ansible_args]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or "Ansible inventory resolution failed")
    lines = proc.stdout.splitlines()
    if not lines or "hosts (" not in lines[0]:
        raise RuntimeError("Unexpected ansible --list-hosts output")
    hosts = [line.strip() for line in lines[1:] if line.strip()]
    if len(hosts) != len(set(hosts)):
        raise RuntimeError("Duplicate hosts in inventory resolution")
    return sorted(hosts)


def review(store: BaselineStore, hosts: list[str]) -> list[dict]:
    result = []
    for host in hosts:
        item = {"host": host, "status": "missing"}
        try:
            latest = store.latest(host)
            item["snapshot_id"] = latest["snapshot_id"]
            item["status"] = "pending"
            try:
                approved = store.approved(host)
                if approved["snapshot_id"] == latest["snapshot_id"]:
                    item["status"] = "approved"
                    item["changes"] = 0
                else:
                    changes = diff(approved["inventory"], latest["inventory"])
                    item["changes"] = len(changes)
                    item["status"] = "changed" if changes else "pending"
            except (OSError, ValueError, KeyError):
                item["changes"] = None
        except (OSError, ValueError, KeyError):
            pass
        result.append(item)
    return result


def manifest_from_review(items: list[dict]) -> dict:
    return {"schema": 1, "approvals": [
        {"host": item["host"], "snapshot_id": item["snapshot_id"]}
        for item in items if "snapshot_id" in item and item["status"] != "approved"
    ]}


def approve_manifest(store: BaselineStore, path: str, confirm: bool) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    approvals = data.get("approvals")
    if data.get("schema") != 1 or not isinstance(approvals, list) or not approvals:
        raise ValueError("Expected nonempty approvals manifest with schema 1")
    seen = set()
    # Validate every entry before changing any baseline pointer.
    for item in approvals:
        if not isinstance(item, dict) or set(item) != {"host", "snapshot_id"}:
            raise ValueError("Each approval requires host and snapshot_id")
        host, snapshot_id = item["host"], item["snapshot_id"]
        if not isinstance(host, str) or not host or host in seen:
            raise ValueError("Invalid or duplicate host")
        seen.add(host)
        if not isinstance(snapshot_id, str):
            raise ValueError("Invalid snapshot id")
        store.snapshot_record(host, snapshot_id)
    if not confirm:
        raise ValueError("Explicit --confirm is required")
    result = []
    for item in approvals:
        store.approve(item["host"], item["snapshot_id"])
        result.append({"host": item["host"], "snapshot_id": item["snapshot_id"]})
    return result
