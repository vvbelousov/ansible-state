"""Read-only drift checks through Ansible's builtin stat module."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from ansible_state.state import Registry


def compare(expected: dict, actual: dict) -> list[str]:
    """Return field-level differences; missing checksums are not evidence of drift."""
    if not actual.get("exists", False):
        return ["missing"]
    differences = []
    if expected.get("checksum") and actual.get("checksum") != expected["checksum"]:
        differences.append("checksum")
    for key in ("mode", "owner", "group"):
        wanted = expected.get("attributes", {}).get(key)
        observed_key = {"owner": "pw_name", "group": "gr_name"}.get(key, key)
        observed = actual.get(observed_key)
        # Missing stat metadata is not evidence of a change.
        if wanted is not None and observed is not None and str(observed) != str(wanted):
            differences.append(key)
    return differences


def check(registry: Registry, inventory_args: list[str] | None = None) -> tuple[int, list[dict]]:
    """Query observed resources. Never execute a mutating module."""
    resources = registry.list_resources()
    if not resources:
        return 0, []
    results = []
    inventory_args = inventory_args or []
    with tempfile.TemporaryDirectory(prefix="ansible-state-drift-") as tmp:
        root = Path(tmp)
        playbook = root / "check.json"
        events = root / "events.jsonl"
        # JSON is valid YAML. Each task targets its recorded host and resource.
        plays = []
        for index, resource in enumerate(resources):
            plays.append({
                "name": f"Inspect managed resource {index}",
                "hosts": resource["host"],
                "gather_facts": False,
                "tasks": [{
                    "name": f"ansible-state inspection {index}",
                    "ansible.builtin.stat": {
                        "path": resource["resource_path"],
                        "get_checksum": True,
                        "checksum_algorithm": "sha1",
                        "follow": False,
                    },
                }],
            })
        playbook.write_text(json.dumps(plays), encoding="utf-8")
        env = os.environ.copy()
        plugin_dir = Path(__file__).resolve().parent / "callback_plugins"
        # Preserve the user's callback paths while enabling ours.
        current = env.get("ANSIBLE_CALLBACK_PLUGINS", "")
        env["ANSIBLE_CALLBACK_PLUGINS"] = os.pathsep.join(
            p for p in (str(plugin_dir), current) if p
        )
        enabled = env.get("ANSIBLE_CALLBACKS_ENABLED", "")
        env["ANSIBLE_CALLBACKS_ENABLED"] = ",".join(
            p for p in (enabled, "state_events") if p
        )
        env["ANSIBLE_STATE_EVENTS"] = str(events)
        env["ANSIBLE_STATE_DRIFT"] = "1"
        try:
            status = subprocess.call(
                ["ansible-playbook", *inventory_args, str(playbook)], env=env
            )
        except FileNotFoundError:
            return 127, [{"status": "error", "reason": "ansible-playbook not found"}]
        if status != 0:
            return status, [{"status": "error", "reason": "inspection failed; results incomplete"}]
        observed = {}
        if events.exists():
            for line in events.read_text(encoding="utf-8").splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("status") != "ok" or "stat" not in event:
                    continue
                index = event.get("inspection_index")
                if isinstance(index, int):
                    observed[(index, event.get("host"))] = event["stat"]
        for index, resource in enumerate(resources):
            actual = observed.get((index, resource["host"]))
            if actual is None:
                results.append({"host": resource["host"], "path": resource["resource_path"],
                                "status": "unknown", "reason": "no stat result"})
                continue
            differences = compare(resource, actual)
            results.append({"host": resource["host"], "path": resource["resource_path"],
                            "status": "drift" if differences else "ok",
                            "differences": differences})
    return 0, results
