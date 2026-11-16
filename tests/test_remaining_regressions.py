"""Regressions from the final review of scoped inventory and migration."""
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest
from test_collection_execution import collector, event, process
from test_scope_regressions import changes, inventory

from ansible_state.baseline import BaselineStore, diff
from ansible_state.inventory import collect
from ansible_state.migration import plan_backfill


@pytest.mark.parametrize("domain", ["filesystem", "sysctl", "firewall", "containers"])
def test_legacy_nonroot_scope_does_not_identify_the_user(domain):
    old = {domain: {"hidden": "1", "shared": "1"}, "_collector_scope": "user"}
    new = {domain: {"newly-visible": "1", "shared": "2"}, "_collector_scope": "user"}
    found = changes(old, new, domain)
    assert not any(c["change"] in {"added", "removed"} for c in found)
    assert any(c.get("reason") == "legacy_scope_unknown" for c in found)
    if domain in {"filesystem", "sysctl"}:
        assert any(c["change"] == "modified" for c in found)
    else:
        assert all(c["change"] == "unknown" for c in found)


def test_ambiguous_legacy_cron_does_not_hide_known_owner_change():
    old = {"cron": {"current_user": "unknown job", "alice": "old job"}}
    new = {"cron": {"alice": "new job"}}
    found = changes(old, new, "cron")
    assert any(c.get("reason") == "legacy_cron_owner_unknown" for c in found)
    assert any(c["change"] == "modified" and c["resource"] == "alice" for c in found)
    assert not any(c["change"] in {"added", "removed"} for c in found)


def test_approved_execution_failure_remains_unknown():
    old = inventory("sysctl", {"a": "1"})
    new = deepcopy(old)
    old["_execution_error"] = {"returncode": 1}
    new["sysctl"]["a"] = "2"
    found = diff(old, new)
    assert any(c.get("reason") == "baseline_execution_failed" and c.get("baseline_error")
               for c in found)
    assert any(c["domain"] == "sysctl" and c["change"] == "modified" for c in found)


@pytest.mark.parametrize("value", ["invalid", 42, False, [], ["a"]])
def test_migration_rejects_malformed_complete_domain(tmp_path, value):
    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"sysctl": None})
    store.approve("host", source)
    plan = plan_backfill(store, "host", inventory("sysctl", value))
    assert "sysctl" not in plan["backfilled"]
    assert "sysctl" in plan["still_unavailable"]
    assert plan["requires_acknowledgement"]
    assert plan["inventory"]["sysctl"] is None


def test_iptables_counter_normalization_preserves_comment_configuration(monkeypatch):
    ns = collector("firewall")
    monkeypatch.setattr(ns["shutil"], "which", lambda cmd: cmd if cmd == "iptables-save" else None)
    run = Mock()
    monkeypatch.setattr(ns["subprocess"], "run", run)

    def observe(packets, comment):
        run.return_value = process(
            f'# Generated at a volatile time\n*filter\n:INPUT ACCEPT [{packets}:99]\n'
            f'[{packets}:99] -A INPUT -m comment --comment "{comment}" -j ACCEPT\nCOMMIT\n')
        return ns["firewall"]()

    first = observe(10, "reference [10:99]")
    assert first == observe(20, "reference [10:99]")
    assert first != observe(20, "reference [20:99]")
    assert "reference [10:99]" in first["iptables"]


def test_unexpected_domain_failure_preserves_other_collections(monkeypatch):
    ns = collector("sysctl")
    for name in ("packages", "services", "listeners", "users", "filesystem", "cron",
                 "timers", "sysctl", "firewall", "containers"):
        ns[name] = Mock(return_value={})
    ns["users"].side_effect = RuntimeError("account database unavailable")
    result = ns["collect_inventory"]()
    assert result["users"] is None
    assert result["sysctl"] == {} and result["containers"] == {}
    assert not result["_collection"]["users"]["complete"]
    assert result["_collection_errors"]["users"][0]["error"] == "account database unavailable"


def test_fallback_does_not_replace_successful_privileged_inventory(monkeypatch):
    calls = []

    def invoke(cmd, env):
        calls.append(cmd)
        if len(calls) == 1:
            events = [event("good"), event("retry", "failed", error="sudo: password is required")]
        else:
            # Unexpected callback output must not overwrite an earlier successful host.
            events = [event("good", uid=1000), event("retry", uid=1000)]
        Path(env["ANSIBLE_STATE_EVENTS"]).write_text("\n".join(json.dumps(e) for e in events))
        return 2 if len(calls) == 1 else 0

    monkeypatch.setattr("ansible_state.inventory.subprocess.call", invoke)
    status, result = collect("all", ["--collector-become"])
    assert status == 0
    assert result["good"]["_collection"]["sysctl"]["scope"] == {"uid": 0}
    assert result["retry"]["_collection"]["sysctl"]["scope"] == {"uid": 1000}


def test_migration_forwards_ansible_connection_options(monkeypatch, tmp_path, capsys):
    from ansible_state.cli import main

    store = BaselineStore(tmp_path)
    source = store.snapshot("host", {"sysctl": None})
    store.approve("host", source)
    resolve = Mock(return_value=["host"])
    run = Mock(return_value=(0, {"host": inventory("sysctl", {"a": "1"})}))
    monkeypatch.setenv("ANSIBLE_STATE_SNAPSHOTS", str(tmp_path))
    monkeypatch.setattr("ansible_state.multi_host.resolve_hosts", resolve)
    monkeypatch.setattr("ansible_state.inventory.collect", run)
    monkeypatch.setattr("sys.argv", ["ansible-state", "baseline", "migrate", "all",
                                    "-i", "hosts.ini", "-u", "operator", "--connection", "local",
                                    "-e", "ansible_become_user=audit", "--collector-become"])
    assert main() == 3  # Other missing domains remain unresolved.
    forwarded = run.call_args.args[1]
    assert forwarded == ["-u", "operator", "--connection", "local",
                         "-e", "ansible_become_user=audit", "-i", "hosts.ini", "--collector-become"]
    resolve.assert_called_once_with("all", forwarded)
    assert json.loads(capsys.readouterr().out)[0]["backfilled"] == ["sysctl"]
    assert store.approved("host")["snapshot_id"] == source


@pytest.mark.parametrize("named", [True, False])
def test_nftables_quota_threshold_is_configuration_usage_is_runtime(monkeypatch, named):
    ns = collector("firewall")
    monkeypatch.setattr(ns["shutil"], "which", lambda cmd: cmd)
    run = Mock()
    monkeypatch.setattr(ns["subprocess"], "run", run)

    def observe(threshold, used, packets):
        quota = {"bytes": threshold, "used": used, "name": "budget"} if named else {
            "val": threshold, "val_unit": "bytes", "used": used, "used_unit": "bytes"}
        run.return_value = process(json.dumps({"nftables": [
            {"metainfo": {"version": str(packets)}},
            {"quota": quota} if named else {"rule": {"handle": packets, "expr": [
                {"quota": quota}, {"counter": {"packets": packets, "bytes": used}}]}},
        ]}))
        return ns["firewall"]()

    first = observe(1024, 0, 0)
    assert first == observe(1024, 512, 10)
    assert first != observe(2048, 512, 10)


def test_old_firewall_normalization_requires_reviewed_observation():
    old = inventory("firewall", {"iptables": 'rule --comment "[0:0]"'})
    new = inventory("firewall", {"iptables": 'rule --comment "[10:20]"'})
    new["_collection"]["firewall"]["scope"]["normalization"] = 2
    found = changes(old, new, "firewall")
    assert found and all(c["change"] == "unknown" for c in found)
    assert found[0]["reason"] == "collection_scope_changed"
