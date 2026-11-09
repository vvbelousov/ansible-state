from ansible_state.baseline import BaselineStore
from ansible_state.migration import plan_backfill


def test_backfill_only_unknown_domains(tmp_path):
    store = BaselineStore(tmp_path)
    original = {"packages": {"nginx": "1"}, "cron": None, "firewall": None}
    sid = store.snapshot("host", original)
    store.approve("host", sid)
    current = {"packages": {"nginx": "2"}, "cron": {"current_user": ""},
               "firewall": {}, "containers": None}
    plan = plan_backfill(store, "host", current)
    assert plan["inventory"]["packages"] == {"nginx": "1"}
    assert plan["inventory"]["cron"] == {"current_user": ""}
    assert plan["inventory"]["firewall"] == {}
    assert plan["source_snapshot_id"] == sid
    assert {"cron", "firewall"} <= set(plan["backfilled"])
    assert "containers" in plan["still_unavailable"]
    assert any(change["domain"] == "packages" for change in plan["existing_changes"])
    assert store.approved("host")["snapshot_id"] == sid


def test_missing_current_data_never_erases_known_baseline(tmp_path):
    store = BaselineStore(tmp_path)
    sid = store.snapshot("host", {"sysctl": {"a": "1"}})
    store.approve("host", sid)
    plan = plan_backfill(store, "host", {"sysctl": None})
    assert plan["inventory"]["sysctl"] == {"a": "1"}
    assert "sysctl" not in plan["backfilled"]
