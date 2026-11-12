import json

import pytest

from ansible_state.baseline import BaselineStore
from ansible_state.multi_host import approve_manifest, manifest_from_review, review


def test_group_review_and_explicit_approval(tmp_path):
    store = BaselineStore(tmp_path / "snapshots")
    a = store.snapshot("ipvs-01", {"packages": {"ipvsadm": "1"}})
    b = store.snapshot("vpn-01", {"packages": {"wireguard": "1"}})
    items = review(store, ["ipvs-01", "vpn-01", "missing"])
    assert [i["status"] for i in items] == ["pending", "pending", "missing"]
    manifest = manifest_from_review(items)
    assert len(manifest["approvals"]) == 2
    path = tmp_path / "approval.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError):
        approve_manifest(store, str(path), False)
    assert store.hosts() == []
    result = approve_manifest(store, str(path), True)
    assert len(result) == 2
    assert store.approved("ipvs-01")["inventory"]["packages"] == {"ipvsadm": "1"}
    assert store.approved("vpn-01")["inventory"]["packages"] == {"wireguard": "1"}
    assert {a, b} == {x["snapshot_id"] for x in result}


def test_manifest_validates_every_host_before_writing(tmp_path):
    store = BaselineStore(tmp_path / "snapshots")
    good = store.snapshot("a", {"packages": {}})
    path = tmp_path / "approval.json"
    path.write_text(json.dumps({"schema": 1, "approvals": [
        {"host": "a", "snapshot_id": good},
        {"host": "b", "snapshot_id": "0" * 32},
    ]}), encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        approve_manifest(store, str(path), True)
    assert store.hosts() == []


def test_latest_snapshot_and_change_review(tmp_path):
    store = BaselineStore(tmp_path)
    first = store.snapshot("host", {"packages": {"nginx": "1"}})
    store.approve("host", first)
    store.snapshot("host", {"packages": {"nginx": "2"}})
    item = review(store, ["host"])[0]
    assert item["status"] == "changed"
    assert item["changes"] >= 1
