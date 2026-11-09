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
    parser.add_argument("command", choices=("apply", "state"))
    args, remaining = parser.parse_known_args()

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
