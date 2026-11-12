from ansible_state.classification import apply_policy, format_report
from ansible_state.inventory import COLLECTOR


def test_remote_collector_compiles():
    compile(COLLECTOR, "collector.py", "exec")


def test_classification_and_ignores():
    changes = [
        {"domain": "packages", "resource": "sortmail", "change": "added"},
        {"domain": "listeners", "resource": "tcp 0.0.0.0:80", "change": "added"},
        {"domain": "services", "resource": "packagekit.service", "change": "modified",
         "baseline": {"unit_file_state": "static", "active_state": "not-loaded"},
         "current": {"unit_file_state": "static", "active_state": "active"}},
    ]
    found = apply_policy(changes, [{"domain": "services", "resource": "packagekit.*"}])
    assert len(found) == 2
    assert found[0]["category"] == "configuration"
    assert found[1]["category"] == "runtime"
    assert found[1]["severity"] == "critical"
    assert "sortmail" in format_report([{"host": "node", "status": "drift", "changes": found}])


def test_service_runtime_only():
    change = {"domain": "services", "resource": "test.service", "change": "modified",
              "baseline": {"unit_file_state": "enabled", "active_state": "inactive"},
              "current": {"unit_file_state": "enabled", "active_state": "active"}}
    assert apply_policy([change], [])[0]["severity"] == "info"
