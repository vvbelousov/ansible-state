import pytest

from ansible_state.baseline import BaselineStore, diff


def test_baseline_is_not_implicitly_approved(tmp_path):
    store = BaselineStore(tmp_path)
    snap = store.snapshot("node", {"packages": {"nginx": "1"}})
    assert store.hosts() == []
    with pytest.raises(FileNotFoundError):
        store.approved("node")
    store.approve("node", snap)
    assert store.hosts() == ["node"]
    assert store.approved("node")["inventory"]["packages"] == {"nginx": "1"}


def test_diff_added_removed_modified_and_unknown():
    old = {"packages": {"nginx": "1", "old": "1"},
           "services": {"nginx.service": "enabled"},
           "listeners": [], "users": {}, "filesystem": {}}
    new = {"packages": {"nginx": "2", "apache2": "1"},
           "services": {"nginx.service": "enabled"},
           "listeners": ["tcp 0.0.0.0:80"], "users": {}, "filesystem": {}}
    changes = diff(old, new)
    assert ("packages", "added") in [(c["domain"], c["change"]) for c in changes]
    assert ("packages", "removed") in [(c["domain"], c["change"]) for c in changes]
    assert ("packages", "modified") in [(c["domain"], c["change"]) for c in changes]
    assert ("listeners", "added") in [(c["domain"], c["change"]) for c in changes]
    assert diff({"packages": None}, {"packages": {}})[0]["change"] == "unknown"

def test_collector_is_valid_python():
    from ansible_state.inventory import COLLECTOR

    compile(COLLECTOR, "remote_collector.py", "exec")


def test_approving_new_snapshot_keeps_old_snapshot(tmp_path):
    store = BaselineStore(tmp_path)
    old = store.snapshot("node", {"packages": {"nginx": "1"}})
    new = store.snapshot("node", {"packages": {"nginx": "2"}})
    store.approve("node", old)
    assert store.approved("node")["inventory"]["packages"]["nginx"] == "1"
    store.approve("node", new)
    assert store.approved("node")["inventory"]["packages"]["nginx"] == "2"
    assert (store._host_dir("node") / f"{old}.json").exists()
