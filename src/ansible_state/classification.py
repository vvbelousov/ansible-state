"""Classify inventory changes without mutating the remote system."""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

RUNTIME_DOMAINS = {"listeners"}
DEFAULT_IGNORES = (
    {"domain": "filesystem", "resource": "/etc/mtab"},
)


def classify(change: dict) -> dict:
    item = dict(change)
    domain = item["domain"]
    runtime = domain in RUNTIME_DOMAINS
    if domain == "services" and item.get("change") == "modified":
        before, after = item.get("baseline", {}), item.get("current", {})
        if isinstance(before, dict) and isinstance(after, dict):
            runtime = before.get("unit_file_state") == after.get("unit_file_state")
    item["category"] = "runtime" if runtime else "configuration"
    if item["change"] == "unknown":
        item["severity"] = "warning"
    elif domain in ("listeners", "users") and item["change"] == "added":
        item["severity"] = "critical"
    elif domain == "services" and item["category"] == "runtime":
        item["severity"] = "info"
    else:
        item["severity"] = "warning"
    return item


def load_policy(path: str | None) -> list[dict]:
    if path is None:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("ignore", []), list):
        raise ValueError("Policy must be a JSON object with an 'ignore' list")
    rules = data.get("ignore", [])
    if any(not isinstance(rule, dict) or
           not isinstance(rule.get("domain"), str) or
           not isinstance(rule.get("resource", "*"), str) for rule in rules):
        raise ValueError("Each ignore rule requires domain and optional resource glob")
    return rules


def apply_policy(changes: list[dict], rules: list[dict]) -> list[dict]:
    result = []
    for change in changes:
        item = classify(change)
        if any(fnmatch.fnmatchcase(item["domain"], rule["domain"]) and
               fnmatch.fnmatchcase(str(item.get("resource", "")), rule.get("resource", "*"))
               for rule in rules):
            continue
        result.append(item)
    return result


def format_report(findings: list[dict]) -> str:
    lines = []
    for host in findings:
        lines.append(f'{host["host"]}: {host["status"].upper()}')
        if "reason" in host:
            lines.append(f'  {host["reason"]}')
        for item in host.get("changes", []):
            lines.append(f'  [{item["severity"].upper()}] {item["category"]} '
                         f'{item["domain"]}:{item.get("resource", "*")} ({item["change"]})')
    return "\n".join(lines)
