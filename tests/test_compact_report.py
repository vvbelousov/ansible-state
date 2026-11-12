"""Text summaries stay readable when collection scope exposes thousands of paths."""
import json
from copy import deepcopy
from types import SimpleNamespace

from ansible_state.baseline import diff
from ansible_state.classification import apply_policy, format_report
from ansible_state.cli import main


def test_thousands_of_unknowns_are_grouped_without_mutating_json():
    errors = [{"resource": f"/etc/private/{i}", "error": "permission denied"} for i in range(40)]
    changes = [{"domain": "filesystem", "resource": f"/etc/private/{i}",
                "change": "unknown", "reason": "baseline_visibility_unknown",
                "category": "configuration", "severity": "warning",
                "baseline_error": errors} for i in range(6603)]
    changes.append({"domain": "filesystem", "resource": "/etc/important", "change": "modified",
                    "category": "configuration", "severity": "warning"})
    findings = [{"host": "node", "status": "drift", "incomplete": True,
                 "has_drift": True, "changes": changes}]
    original = json.dumps(findings)
    report = format_report(findings)
    assert len(report.splitlines()) < 20
    assert len(report) < 2000
    assert "6603 unknown finding(s)" in report
    assert "/etc/important (modified)" in report
    assert "confirmed drift" in report
    assert report.count("Baseline filesystem:") == 1
    assert "40 diagnostic(s)" in report and "38 more diagnostic(s)" in report
    assert "--report-format json" in report
    assert json.dumps(findings) == original


def test_configuration_changes_get_space_even_after_many_runtime_changes():
    changes = [{"domain": "listeners", "resource": f"tcp 0.0.0.0:{i}", "change": "added",
                "category": "runtime", "severity": "critical"} for i in range(100)]
    changes += [{"domain": "filesystem", "resource": f"/etc/{i}", "change": "modified",
                 "category": "configuration", "severity": "warning"} for i in range(100)]
    report = format_report([{"host": "node", "status": "drift", "changes": changes}])
    assert "Configuration changes: 100; runtime changes: 100" in report
    assert "filesystem:/etc/0" in report
    assert "80 more configuration change(s)" in report
    assert "95 more runtime change(s)" in report
    assert len(report.splitlines()) < 35


def test_diagnostics_are_deduplicated_and_sources_are_separate():
    baseline_errors = [{"error": "historical permission denied"}]
    current_errors = [{"error": "current connection failed"}]
    changes = apply_policy(diff(
        {"sysctl": {"a": "1"}, "_collection_errors": {"sysctl": baseline_errors}},
        {"sysctl": {}, "_collection_errors": {"sysctl": current_errors}},
    ), [])
    report = format_report([{"host": "node", "status": "incomplete", "changes": changes}])
    assert report.count("historical permission denied") == 1
    assert report.count("current connection failed") == 1
    assert "Baseline sysctl:" in report and "Collector sysctl:" in report


def test_multiline_diagnostics_cannot_flood_terminal():
    changes = [{"domain": "firewall", "change": "unknown", "reason": "collection_unavailable",
                "collector_error": {"error": "denied\n" * 1000}}]
    report = format_report([{"host": "node", "status": "incomplete", "changes": changes}])
    assert len(report) < 1000
    assert len(report.splitlines()) < 10


def test_cli_preserves_baseline_diagnostic_in_json(monkeypatch, tmp_path, capsys):
    from ansible_state.baseline import BaselineStore

    store = BaselineStore(tmp_path)
    old = {"sysctl": {"a": "1"}, "_collection_errors": {"sysctl": {"error": "old error"}}}
    source = store.snapshot("host", old)
    store.approve("host", source)
    current = {"sysctl": {}, "_collection_errors": {"sysctl": {"error": "new error"}}}
    original = deepcopy(current)
    monkeypatch.setenv("ANSIBLE_STATE_SNAPSHOTS", str(tmp_path))
    monkeypatch.setattr("ansible_state.multi_host.resolve_hosts", lambda *a: ["host"])
    monkeypatch.setattr("ansible_state.inventory.collect", lambda *a, **kw: (0, {"host": current}))
    monkeypatch.setattr("sys.argv", ["ansible-state", "system-drift", "all", "--report-format", "json"])
    assert main() == 3
    findings = json.loads(capsys.readouterr().out)
    baseline = next(c for c in findings[0]["changes"] if c.get("reason") == "baseline_partial")
    assert baseline["baseline_error"] == {"error": "old error"}
    assert current == original


def test_callback_records_privilege_failure_from_stdout(monkeypatch, tmp_path):
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path / "ansible-local"))
    from ansible_state.callback_plugins.state_events import CallbackModule

    path = tmp_path / "events.jsonl"
    monkeypatch.setenv("ANSIBLE_STATE_EVENTS", str(path))
    monkeypatch.setenv("ANSIBLE_STATE_INVENTORY", "1")
    result = SimpleNamespace(
        _task=SimpleNamespace(action="ansible.builtin.script", args={},
                              get_name=lambda: "ansible-state inventory"),
        _host=SimpleNamespace(get_name=lambda: "px-01"),
        _result={"msg": "non-zero return code", "stdout": "/bin/sh: 1: sudo: not found",
                 "stderr": "Shared connection closed"},
    )
    CallbackModule().v2_runner_on_failed(result)
    event = json.loads(path.read_text())
    assert "sudo: not found" in event["error"]
