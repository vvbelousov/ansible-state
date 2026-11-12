from ansible_state.baseline import BaselineStore, diff
from ansible_state.classification import apply_policy, format_report
from ansible_state.multi_host import review


def test_approved_snapshot_exposes_id(tmp_path):
    store = BaselineStore(tmp_path)
    sid = store.snapshot("host1", {"packages": {"bash": "1"}})
    store.approve("host1", sid)
    assert store.approved("host1")["snapshot_id"] == sid
    assert review(store, ["host1"])[0]["status"] == "approved"


def test_incomplete_reason_is_not_silently_clean():
    expected = {"cron": None, "firewall": None}
    actual = {"cron": {"current_user": ""}, "firewall": {}}
    changes = apply_policy(diff(expected, actual), [])
    changes = [c for c in changes if c["domain"] in {"cron", "firewall"}]
    assert len(changes) == 2
    assert all(change["reason"] == "baseline_unavailable" for change in changes)
    report = format_report([{"host": "host1", "status": "incomplete", "changes": changes}])
    assert "baseline_unavailable" in report


def test_collection_failure_distinct_from_legacy_baseline():
    changes = diff({"cron": {"current_user": ""}}, {"cron": None})
    cron = next(item for item in changes if item["domain"] == "cron")
    assert cron["reason"] == "collection_unavailable"
