"""Transparent Ansible CLI entry point.

No playbook modification or custom Ansible execution engine is required.
The initial milestone intentionally implements execution only; no destructive
state reconciliation is enabled.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ansible-state",
        description="Run existing Ansible playbooks with optional state tracking.",
    )
    parser.add_argument(
        "command", choices=("apply",), help="Execute a playbook (v0.1 bootstrap)"
    )
    args, remaining = parser.parse_known_args()
    if args.command == "apply":
        if not remaining:
            parser.error("apply requires a playbook path and/or ansible-playbook arguments")
        try:
            return subprocess.call(["ansible-playbook", *remaining])
        except FileNotFoundError:
            print("ansible-playbook executable not found", file=sys.stderr)
            return 127
    return 2


if __name__ == "__main__":
    sys.exit(main())
