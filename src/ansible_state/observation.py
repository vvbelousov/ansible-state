"""Parse Ansible callback events conservatively.

Only explicit successful file operations with an unambiguous destination are
registered. This is not a complete desired-state representation.
"""
from __future__ import annotations

import json
from pathlib import Path

from ansible_state.state import Registry

SUPPORTED = {"ansible.builtin.copy", "copy", "ansible.builtin.template",
             "template", "ansible.builtin.file", "file"}


def ingest(path: Path, registry: Registry, run_id: str) -> int:
    count = 0
    if not path.exists():
        return count
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("status") != "ok" or event.get("action") not in SUPPORTED:
            continue
        result = event.get("result", {})
        args = event.get("args", {})
        destination = result.get("dest") or result.get("path") or args.get("dest") or args.get("path")
        if not isinstance(destination, str) or not destination.startswith("/"):
            continue
        if result.get("state") == "absent" or args.get("state") == "absent":
            continue
        host = event.get("host")
        if not isinstance(host, str) or not host:
            continue
        attrs = {k: result[k] for k in ("mode", "owner", "group", "state", "size")
                 if k in result}
        registry.record(host, event["action"], destination,
                        result.get("checksum"), attrs, run_id)
        count += 1
    return count
