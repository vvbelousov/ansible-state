from ansible_state.baseline import BaselineStore
from ansible_state.migration import plan_backfill


def test_backfill_only_unknown_domains(tmp_path):
    store = BaselineStore(tmp_path)
    original = {"packages": {"nginx": "1"}, "cron": None, "firewall": None}
    sid = store.snapshot("host", original)
    store.approve("host", sid)
    current = {"packages": {"nginx": "2"}, "cron": {"root": ""},
               "firewall": {}, "containers": None}
    current["_collection"] = {
        "cron": {"scope": {"owner": "root"}, "complete": True},
        "firewall": {"scope": {"uid": 0}, "complete": True},
    }
    plan = plan_backfill(store, "host", current)
    assert plan["inventory"]["packages"] == {"nginx": "1"}
    assert plan["inventory"]["cron"] == {"root": ""}
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


def test_partial_domain_is_not_backfilled(tmp_path):
    store = BaselineStore(tmp_path)
    sid = store.snapshot("host", {"sysctl": None})
    store.approve("host", sid)
    plan = plan_backfill(store, "host", {
        "_collector_scope": "root", "_partial_domains": ["sysctl"],
        "sysctl": {"net.ipv4.ip_forward": "1"}})
    assert plan["inventory"]["sysctl"] is None
    assert "sysctl" in plan["still_unavailable"]
    assert "sysctl" not in plan["backfilled"]


def test_backfill_records_collector_provenance(tmp_path):
    store = BaselineStore(tmp_path)
    sid = store.snapshot("host", {"firewall": None})
    store.approve("host", sid)
    plan = plan_backfill(store, "host", {
        "_collection": {"firewall": {"scope": {"uid": 0}, "complete": True}},
        "firewall": {"nftables": {}}})
    provenance = plan["inventory"]["_provenance"]["firewall"]
    assert provenance["scope"] == {"uid": 0}
    assert provenance["source_snapshot_id"] == sid
    assert provenance["backfilled_at"]


def test_candidate_warnings_require_explicit_acknowledgement(tmp_path):
    import pytest

    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"packages": {"app": "1"}, "cron": None})
    store.approve("host", source)
    plan = plan_backfill(store, "host", {
        "packages": {"app": "2"}, "cron": {"root": ""},
        "_collection": {"cron": {"scope": {"owner": "root"}, "complete": True}},
    })
    candidate = store.snapshot("host", plan["inventory"])
    assert plan["requires_acknowledgement"]
    assert plan["existing_changes"] and plan["unresolved"]
    with pytest.raises(ValueError, match="accept-migration-warnings"):
        store.approve("host", candidate)
    assert store.approved("host")["snapshot_id"] == source
    store.approve("host", candidate, accept_migration_warnings=True)
    assert store.approved("host")["inventory"]["packages"] == {"app": "1"}
    assert store.snapshot_record("host", source)["inventory"]["cron"] is None
    # Retrying an already applied manifest is safe.
    store.approve("host", candidate, accept_migration_warnings=True)


def test_backfill_never_uses_unverified_or_failed_results(tmp_path):
    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"sysctl": None})
    store.approve("host", source)
    for current in [
        {"sysctl": {"a": "1"}},
        {"sysctl": {"a": "1"}, "_collection": {
            "sysctl": {"scope": {"uid": 0}, "complete": False}}},
        {"sysctl": {"a": "1"}, "_collection": {
            "sysctl": {"scope": {"uid": 0}, "complete": True, "errors": [{"error": "denied"}]}}},
    ]:
        plan = plan_backfill(store, "host", current)
        assert "sysctl" not in plan["backfilled"]
        assert plan["inventory"]["sysctl"] is None


def test_stale_migration_source_cannot_be_approved(tmp_path):
    import pytest

    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"packages": {}})
    store.approve("host", source)
    plan = plan_backfill(store, "host", {})
    candidate = store.snapshot("host", plan["inventory"])
    newer = store.snapshot("host", {"packages": {"app": "1"}})
    store.approve("host", newer)
    with pytest.raises(ValueError, match="source baseline changed"):
        store.approve("host", candidate, accept_migration_warnings=True)


def test_backfilled_scope_overrides_historical_host_scope(tmp_path):
    from ansible_state.baseline import diff

    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"_collector_scope": "user", "sysctl": None})
    store.approve("host", source)
    current = {"sysctl": {"a": "1"}, "_collection": {
        "sysctl": {"scope": {"uid": 0}, "complete": True}}}
    plan = plan_backfill(store, "host", current)
    current["sysctl"]["a"] = "2"
    found = [c for c in diff(plan["inventory"], current) if c["domain"] == "sysctl"]
    assert len(found) == 1 and found[0]["change"] == "modified"
    assert plan["inventory"]["sysctl"]["a"] == "1"


def test_old_backfill_provenance_overrides_old_global_scope():
    from ansible_state.baseline import domain_metadata

    old = {"_collector_scope": "user", "sysctl": {},
           "_backfill_provenance": {"sysctl": {"collector_scope": "root"}}}
    assert domain_metadata(old, "sysctl")["scope"] == {"uid": 0}
