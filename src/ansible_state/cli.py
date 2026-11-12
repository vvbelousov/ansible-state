"""Transparent CLI with opt-in read-only resource observation."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from ansible_state.observation import ingest
from ansible_state.state import Registry


def main() -> int:
    parser = argparse.ArgumentParser(prog="ansible-state")
    parser.add_argument("command", choices=("apply", "state", "drift", "snapshot", "baseline", "system-drift"))
    args, remaining = parser.parse_known_args()

    if args.command in ("snapshot", "baseline", "system-drift"):
        from ansible_state.baseline import DOMAINS, BaselineStore, diff, domain_metadata
        from ansible_state.inventory import collect
        store = BaselineStore(os.environ.get("ANSIBLE_STATE_SNAPSHOTS", ".ansible-state/snapshots"))
        if args.command == "baseline":
            from ansible_state.multi_host import (
                approve_manifest,
                manifest_from_review,
                resolve_hosts,
                review,
            )
            if remaining[:1] == ["migrate"]:
                migration_parser = argparse.ArgumentParser(prog="ansible-state baseline migrate")
                migration_parser.add_argument("pattern")
                migration_parser.add_argument("--prepare", action="store_true")
                migration_parser.add_argument("--collector-become", action="store_true")
                migration_parser.add_argument("--write-manifest")
                migration_parser.add_argument("-i", "--inventory", action="append")
                migration_args = migration_parser.parse_args(remaining[1:])
                if migration_args.write_manifest and not migration_args.prepare:
                    migration_parser.error("--write-manifest requires --prepare")
                forwarded = []
                for inventory_path in migration_args.inventory or []:
                    forwarded.extend(["-i", inventory_path])
                if migration_args.collector_become:
                    forwarded.append("--collector-become")
                from ansible_state.migration import plan_backfill
                try:
                    selected = resolve_hosts(migration_args.pattern, forwarded)
                    if not selected:
                        raise ValueError("Host pattern matched no hosts")
                    status, collected = collect(migration_args.pattern, forwarded, fallback_hosts=selected)
                    results = []
                    approvals = []
                    for host in selected:
                        if host not in collected:
                            results.append({"host": host, "status": "unreachable"})
                            continue
                        try:
                            plan = plan_backfill(store, host, collected[host])
                        except (OSError, ValueError, TypeError, KeyError) as exc:
                            results.append({"host": host, "status": "no_baseline", "reason": str(exc)})
                            continue
                        result = {"host": host, "status": "review",
                                  "source_snapshot_id": plan["source_snapshot_id"],
                                  "backfilled": plan["backfilled"],
                                  "still_unavailable": plan["still_unavailable"],
                                  "existing_changes": plan["existing_changes"],
                                  "unresolved": plan["unresolved"],
                                  "requires_acknowledgement": plan["requires_acknowledgement"]}
                        if migration_args.prepare and plan["backfilled"]:
                            candidate_id = store.snapshot(host, plan["inventory"])
                            result["candidate_snapshot_id"] = candidate_id
                            approvals.append({"host": host, "snapshot_id": candidate_id})
                        results.append(result)
                    if migration_args.write_manifest:
                        Path(migration_args.write_manifest).write_text(
                            json.dumps({"schema": 1, "approvals": approvals}, indent=2),
                            encoding="utf-8",
                        )
                    print(json.dumps(results, indent=2, ensure_ascii=False))
                    return status or (3 if any(r["status"] != "review" or
                                              r.get("requires_acknowledgement") for r in results) else 0)
                except (OSError, ValueError, RuntimeError) as exc:
                    print(f"Baseline migration failed: {exc}", file=sys.stderr)
                    return 2
            if remaining and remaining[0] == "status" and len(remaining) >= 2:
                pattern, *options = remaining[1:]
                manifest_path = None
                if "--write-manifest" in options:
                    idx = options.index("--write-manifest")
                    if idx + 1 >= len(options):
                        parser.error("--write-manifest requires a path")
                    manifest_path = options[idx + 1]
                    options = options[:idx] + options[idx + 2:]
                try:
                    hosts = resolve_hosts(pattern, options)
                    if not hosts:
                        raise ValueError("Host pattern matched no hosts")
                    items = review(store, hosts)
                    if manifest_path:
                        Path(manifest_path).write_text(
                            json.dumps(manifest_from_review(items), indent=2), encoding="utf-8"
                        )
                except (OSError, ValueError, RuntimeError) as exc:
                    print(f"Baseline status failed: {exc}", file=sys.stderr)
                    return 2
                print(json.dumps(items, indent=2))
                return 3 if any(item["status"] != "approved" for item in items) else 0
            if remaining[:1] == ["approve"] and "--manifest" in remaining:
                idx = remaining.index("--manifest")
                if idx + 1 >= len(remaining):
                    parser.error("--manifest requires a path")
                if set(remaining[1:idx] + remaining[idx + 2:]) - {"--confirm", "--accept-migration-warnings"}:
                    parser.error("usage: baseline approve --manifest FILE --confirm")
                try:
                    result = approve_manifest(store, remaining[idx + 1], "--confirm" in remaining,
                                              "--accept-migration-warnings" in remaining)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    print(f"Baseline approval failed: {exc}", file=sys.stderr)
                    return 2
                print(json.dumps(result, indent=2))
                return 0
            accept_warnings = "--accept-migration-warnings" in remaining
            remaining = [arg for arg in remaining if arg != "--accept-migration-warnings"]
            if len(remaining) != 3 or remaining[0] != "approve":
                parser.error("usage: baseline status PATTERN [-i INVENTORY] [--write-manifest FILE] | baseline approve --manifest FILE --confirm | baseline approve HOST SNAPSHOT_ID")
            _, host, snapshot_id = remaining
            try:
                store.approve(host, snapshot_id, accept_warnings)
            except (OSError, ValueError, TypeError) as exc:
                print(f"Baseline approval failed: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"host": host, "approved_snapshot": snapshot_id}))
            return 0
        if args.command == "snapshot":
            if not remaining:
                parser.error("usage: ansible-state snapshot HOST_PATTERN [ansible-playbook options]")
            host_pattern, *options = remaining
            from ansible_state.multi_host import resolve_hosts
            try:
                selected = resolve_hosts(host_pattern, options)
            except (OSError, RuntimeError) as exc:
                print(f"Inventory resolution failed: {exc}", file=sys.stderr)
                return 2
            if not selected:
                print("Host pattern matched no hosts", file=sys.stderr)
                return 2
            status, collected = collect(host_pattern, options, fallback_hosts=selected)
            rows = []
            for host in selected:
                if host not in collected:
                    rows.append({"host": host, "status": "failed"})
                    continue
                data = collected[host]
                incomplete_domains = [domain for domain in DOMAINS
                                      if domain_metadata(data, domain).get("complete") is False]
                rows.append({"host": host, "snapshot_id": store.snapshot(host, data),
                             "status": "partial" if incomplete_domains or data.get("_execution_error") else "collected",
                             "incomplete_domains": incomplete_domains})
            print(json.dumps(rows, indent=2))
            return status or (3 if any(row["status"] != "collected" for row in rows) else 0)
        # system-drift: only explicitly approved hosts, never update baseline.
        if not remaining:
            parser.error("usage: ansible-state system-drift HOST_PATTERN [ansible-playbook options]")
        host_pattern, *options = remaining
        from ansible_state.classification import (
            apply_policy,
            format_report,
            load_policy,
        )
        report_format = "json"
        policy_path = None
        # Our flags are parsed explicitly; all other options go to ansible-playbook.
        forwarded = []
        index = 0
        while index < len(options):
            if options[index] in ("--report-format", "--policy"):
                if index + 1 >= len(options):
                    parser.error(f"{options[index]} requires a value")
                value = options[index + 1]
                if options[index] == "--report-format":
                    if value not in ("json", "text"):
                        parser.error("--report-format must be json or text")
                    report_format = value
                else:
                    policy_path = value
                index += 2
            else:
                forwarded.append(options[index])
                index += 1
        try:
            rules = load_policy(policy_path)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(f"Invalid drift policy: {exc}")
        from ansible_state.multi_host import resolve_hosts
        try:
            selected = resolve_hosts(host_pattern, forwarded)
        except (OSError, RuntimeError) as exc:
            print(f"Inventory resolution failed: {exc}", file=sys.stderr)
            return 2
        if not selected:
            print("Host pattern matched no hosts", file=sys.stderr)
            return 2
        status, collected = collect(host_pattern, forwarded, fallback_hosts=selected)
        findings = [{"host": host, "status": "incomplete", "incomplete": True,
                     "has_drift": False, "has_runtime_changes": False,
                     "reason": "Host collection failed or returned no inventory"}
                    for host in selected if host not in collected]
        for host, data in sorted(collected.items()):
            try:
                approved = store.approved(host)
                changes = apply_policy(diff(approved["inventory"], data), rules)
                incomplete = any(change["change"] == "unknown" for change in changes)
                has_drift = any(change["change"] != "unknown" and
                                change["category"] != "runtime" for change in changes)
                runtime_changes = any(change["change"] != "unknown" and
                                      change["category"] == "runtime" for change in changes)
                findings.append({"host": host,
                                 "status": "drift" if has_drift else ("incomplete" if incomplete else "ok"),
                                 "incomplete": incomplete,
                                 "has_drift": has_drift,
                                 "has_runtime_changes": runtime_changes,
                                 "changes": changes})
            except (OSError, ValueError, TypeError, KeyError) as exc:
                findings.append({"host": host, "status": "incomplete", "incomplete": True,
                                 "has_drift": False, "has_runtime_changes": False,
                                 "reason": f"No valid approved baseline: {exc}"})
        if report_format == "text":
            from collections import Counter
            counts = Counter(item["status"] for item in findings)
            print("INFRASTRUCTURE AUDIT: " + ", ".join(
                f"{name}={counts[name]}" for name in ("ok", "drift", "incomplete", "unknown")
            ) + f", drift_and_incomplete={sum(1 for item in findings if item.get('has_drift') and item.get('incomplete'))}")
            print(format_report(findings))
        else:
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        return status or (3 if any(item["status"] != "ok" for item in findings) else 0)

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
