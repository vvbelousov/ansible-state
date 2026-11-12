"""Classify inventory changes without mutating the remote system."""
from __future__ import annotations

import fnmatch
import json
from collections import defaultdict
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
    if domain == "containers" and item.get("change") == "modified":
        before, after = item.get("baseline", {}), item.get("current", {})
        if isinstance(before, dict) and isinstance(after, dict):
            runtime = before.get("image") == after.get("image")
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
        raise TypeError("Policy must be a JSON object with an 'ignore' list")
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
        if item["change"] != "unknown" and any(fnmatch.fnmatchcase(item["domain"], rule["domain"]) and
               fnmatch.fnmatchcase(str(item.get("resource", "")), rule.get("resource", "*"))
               for rule in rules):
            continue
        result.append(item)
    return result


def _short(value: object, limit: int = 180) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _format_diagnostics(changes: list[dict]) -> list[str]:
    """Print each domain/source's diagnostics once, with bounded examples."""
    diagnostics = defaultdict(dict)
    seen = set()
    for item in changes:
        for field, source in (("baseline_error", "Baseline"), ("collector_error", "Collector")):
            errors = item.get(field)
            if not errors:
                continue
            key = (item["domain"], source)
            identity = (*key, id(errors))
            if identity in seen:
                continue
            seen.add(identity)
            for error in errors if isinstance(errors, list) else [errors]:
                signature = json.dumps(error, sort_keys=True, ensure_ascii=False)
                diagnostics[key][signature] = error
    lines = []
    for (domain, source), errors in sorted(diagnostics.items())[:20]:
        lines.append(f"  {source} {domain}: {len(errors)} diagnostic(s)")
        for error in list(errors.values())[:2]:
            lines.append(f"    {_short(json.dumps(error, ensure_ascii=False))}")
        if len(errors) > 2:
            lines.append(f"    ... {len(errors) - 2} more diagnostic(s)")
    if len(diagnostics) > 20:
        lines.append(f"  ... {len(diagnostics) - 20} more diagnostic groups")
    return lines


def format_report(findings: list[dict]) -> str:
    """Bound text output per host; JSON retains every finding and diagnostic."""
    lines = []
    for host in findings:
        lines.append(f'{host["host"]}: {host["status"].upper()}')
        if "reason" in host:
            lines.append(f'  {_short(host["reason"])}')
        if host.get("incomplete") and host.get("has_drift"):
            lines.append("  NOTE: confirmed drift; some inventory domains remain unavailable")
        changes = host.get("changes", [])
        configuration, runtime = [], []
        unknown = defaultdict(list)
        for item in changes:
            if item["change"] == "unknown":
                unknown[(item["domain"], item.get("reason", "unspecified"))].append(item)
            elif item["category"] == "runtime":
                runtime.append(item)
            else:
                configuration.append(item)
        if changes:
            lines.append(f"  Configuration changes: {len(configuration)}; runtime changes: {len(runtime)}; "
                         f"unknown findings: {sum(len(items) for items in unknown.values())}")
        for label, items, limit in (("configuration", configuration, 20), ("runtime", runtime, 5)):
            for item in items[:limit]:
                lines.append(f'  [{item["severity"].upper()}] {label} '
                             f'{item["domain"]}:{_short(item.get("resource", "*"))} ({item["change"]})')
            if len(items) > limit:
                lines.append(f"  ... {len(items) - limit} more {label} change(s)")
        for (domain, reason), items in sorted(unknown.items())[:20]:
            lines.append(f"  [WARNING] {domain}: {len(items)} unknown finding(s) ({_short(reason)})")
            resources = [item["resource"] for item in items if "resource" in item]
            if resources:
                lines.append("    Examples: " + "; ".join(_short(resource, 120) for resource in resources[:3]))
        if len(unknown) > 20:
            lines.append(f"  ... {len(unknown) - 20} more unknown groups")
        lines.extend(_format_diagnostics(changes))
        if unknown or len(configuration) > 20 or len(runtime) > 5:
            lines.append("  Full findings and diagnostics: rerun with --report-format json")
    return "\n".join(lines)
