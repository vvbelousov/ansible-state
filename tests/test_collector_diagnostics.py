from ansible_state.classification import format_report
from ansible_state.inventory import COLLECTOR


def test_collector_compiles_with_diagnostics():
    compile(COLLECTOR, "collector.py", "exec")


def test_mixed_drift_and_incomplete_are_visible():
    report = format_report([{
        "host": "node", "status": "drift", "incomplete": True,
        "has_drift": True,
        "changes": [
            {"domain": "users", "resource": "unexpected", "change": "added",
             "category": "configuration", "severity": "critical"},
            {"domain": "firewall", "change": "unknown",
             "category": "configuration", "severity": "warning",
             "reason": "baseline_unavailable",
             "collector_error": {"command": "nft", "returncode": 1,
                                 "error": "Operation not permitted"}},
        ],
    }])
    assert "confirmed drift" in report
    assert "Operation not permitted" in report
    assert "users:unexpected" in report
