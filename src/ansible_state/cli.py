"""Transparent CLI with opt-in read-only resource observation."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from ansible_state.observation import ingest
from ansible_state.state import Registry


def main() -> int:
    parser = argparse.ArgumentParser(prog="ansible-state")
    parser.add_argument("command", choices=("apply", "state", "drift", "snapshot", "baseline", "system-drift"))
    args, remaining = parser.parse_known_args()

    if args.command in ("snapshot", "baseline", "system-drift"):
        from ansible_state.baseline import BaselineStore, diff
        from ansible_state.inventory import collect
        store = BaselineStore(os.environ.get("ANSIBLE_STATE_SNAPSHOTS", ".ansible-state/snapshots"))
        if args.command == "baseline":
            if len(remaining) != 3 or remaining[0] != "approve":
                parser.error("usage: ansible-state baseline approve HOST SNAPSHOT_ID")
            _, host, snapshot_id = remaining
            try:
                store.approve(host, snapshot_id)
            except (OSError, ValueError) as exc:
                print(f"Baseline approval failed: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"host": host, "approved_snapshot": snapshot_id}))
            return 0
        if args.command == "snapshot":
            if not remaining:
                parser.error("usage: ansible-state snapshot HOST_PATTERN [ansible-playbook options]")
            host_pattern, *options = remaining
            status, collected = collect(host_pattern, options)
            if status:
                print("Inventory collection failed or incomplete", file=sys.stderr)
                return status
            print(json.dumps([{"host": host, "snapshot_id": store.snapshot(host, data)}
                              for host, data in sorted(collected.items())], indent=2))
            return 0
        # system-drift: only explicitly approved hosts, never update baseline.
        if not remaining:
            parser.error("usage: ansible-state system-drift HOST_PATTERN [ansible-playbook options]")
        host_pattern, *options = remaining
        status, collected = collect(host_pattern, options)
        if status:
            print("Inventory collection failed or incomplete", file=sys.stderr)
            return status
        findings = []
        for host, data in sorted(collected.items()):
            try:
                approved = store.approved(host)
                changes = diff(approved["inventory"], data)
                findings.append({"host": host, "status": "drift" if changes else "ok",
                                 "changes": changes})
            except (OSError, ValueError, KeyError) as exc:
                findings.append({"host": host, "status": "unknown",
                                 "reason": f"No valid approved baseline: {exc}"})
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return 3 if any(item["status"] != "ok" for item in findings) else 0

    if args.command == "drift":
        from ansible_state.drift import check
        db = Registry(os.environ.get("ANSIBLE_STATE_DB", ".ansible-state/state.db"))
        try:
            status, findings = check(db, remaining)
        finally:
            db.close()
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return status if status else (3 if any(f["status"] != "ok" for f in findings) else 0)

    if args.command == "state":
        if remaining:
            parser.error("state does not accept playbook arguments")
        db = Registry(os.environ.get("ANSIBLE_STATE_DB", ".ansible-state/state.db"))
        try:
            print(json.dumps(db.list_resources(), indent=2, ensure_ascii=False))
        finally:
            db.close()
        return 0

    if not remaining:
        parser.error("apply requires ansible-playbook arguments")

    # Preserve the original execution environment unless the user explicitly
    # opted into callback observation. Never override user callback settings.
    if os.environ.get("ANSIBLE_CALLBACK_PLUGINS") or os.environ.get("ANSIBLE_CALLBACKS_ENABLED"):
        print("Observation disabled: existing callback configuration detected", file=sys.stderr)
        try:
            return subprocess.call(["ansible-playbook", *remaining])
        except FileNotFoundError:
            print("ansible-playbook executable not found", file=sys.stderr)
            return 127

    plugin_dir = Path(__file__).resolve().parent / "callback_plugins"
    with tempfile.TemporaryDirectory(prefix="ansible-state-") as tmp:
        event_path = Path(tmp) / "events.jsonl"
        env = os.environ.copy()
        env["ANSIBLE_CALLBACK_PLUGINS"] = str(plugin_dir)
        env["ANSIBLE_CALLBACKS_ENABLED"] = "state_events"
        env["ANSIBLE_STATE_EVENTS"] = str(event_path)
        try:
            status = subprocess.call(["ansible-playbook", *remaining], env=env)
        except FileNotFoundError:
            print("ansible-playbook executable not found", file=sys.stderr)
            return 127
        if status == 0:
            db = Registry(os.environ.get("ANSIBLE_STATE_DB", ".ansible-state/state.db"))
            try:
                ingest(event_path, db, uuid.uuid4().hex)
            finally:
                db.close()
        else:
            print("State not committed: Ansible run did not succeed", file=sys.stderr)
        return status


if __name__ == "__main__":
    sys.exit(main())
