import json
from copy import deepcopy

import pytest
from test_scope_regressions import inventory

from ansible_state.baseline import DOMAINS, BaselineStore
from ansible_state.cli import main
from ansible_state.multi_host import approve_manifest


@pytest.mark.parametrize("mode,expected_status,code", [
    ("clean", "ok", 0), ("runtime", "ok", 0),
    ("drift", "drift", 3), ("partial", "incomplete", 3), ("mixed", "drift", 3),
])
def test_audit_status_and_flags(monkeypatch, tmp_path, capsys, mode, expected_status, code):
    old = inventory("sysctl", {"a": "1"})
    old["cron"] = {"root": ""}
    old["listeners"] = []
    old["_collection"].update({
        domain: {"scope": {"owner": "root"} if domain == "cron" else {"uid": 0}, "complete": True}
        for domain in DOMAINS
    })
    current = deepcopy(old)
    if mode in {"drift", "mixed"}:
        current["sysctl"]["a"] = "2"
    if mode in {"partial", "mixed"}:
        current["firewall"] = None
        current["_collection"]["firewall"]["complete"] = False
    if mode == "runtime":
        current["listeners"] = ["tcp 0.0.0.0:80"]
    store = BaselineStore(tmp_path)
    source = store.snapshot("host", old)
    store.approve("host", source)
    monkeypatch.setenv("ANSIBLE_STATE_SNAPSHOTS", str(tmp_path))
    monkeypatch.setattr("ansible_state.multi_host.resolve_hosts", lambda *a: ["host"])
    monkeypatch.setattr("ansible_state.inventory.collect", lambda *a, **kw: (0, {"host": current}))
    monkeypatch.setattr("sys.argv", ["ansible-state", "system-drift", "all"])
    assert main() == code
    result = json.loads(capsys.readouterr().out)[0]
    assert result["status"] == expected_status
    assert result["has_drift"] == (mode in {"drift", "mixed"})
    assert result["incomplete"] == (mode in {"partial", "mixed"})
    assert result["has_runtime_changes"] == (mode == "runtime")


def test_prepare_reports_drift_and_manifest_cannot_bypass_warnings(monkeypatch, tmp_path, capsys):
    store = BaselineStore(tmp_path / "snapshots")
    source = store.snapshot("host", {"packages": {"app": "1"}, "sysctl": None})
    store.approve("host", source)
    current = inventory("sysctl", {"a": "1"})
    current["packages"] = {"app": "2"}
    manifest = tmp_path / "approval.json"
    monkeypatch.setenv("ANSIBLE_STATE_SNAPSHOTS", str(store.root))
    monkeypatch.setattr("ansible_state.multi_host.resolve_hosts", lambda *a: ["host"])
    monkeypatch.setattr("ansible_state.inventory.collect", lambda *a, **kw: (0, {"host": current}))
    monkeypatch.setattr("sys.argv", ["ansible-state", "baseline", "migrate", "all", "--prepare",
                                    "--write-manifest", str(manifest)])
    assert main() == 3
    result = json.loads(capsys.readouterr().out)[0]
    assert result["existing_changes"] and result["requires_acknowledgement"]
    assert result["candidate_snapshot_id"]
    assert store.approved("host")["snapshot_id"] == source
    with pytest.raises(ValueError, match="accept-migration-warnings"):
        approve_manifest(store, str(manifest), True)
    approve_manifest(store, str(manifest), True, accept_migration_warnings=True)
    assert store.approved("host")["inventory"]["packages"] == {"app": "1"}


def test_failed_host_is_incomplete_not_clean(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ANSIBLE_STATE_SNAPSHOTS", str(tmp_path))
    monkeypatch.setattr("ansible_state.multi_host.resolve_hosts", lambda *a: ["offline"])
    monkeypatch.setattr("ansible_state.inventory.collect", lambda *a, **kw: (2, {}))
    monkeypatch.setattr("sys.argv", ["ansible-state", "system-drift", "all"])
    assert main() == 2
    result = json.loads(capsys.readouterr().out)[0]
    assert result["status"] == "incomplete" and result["incomplete"]
