"""Run remote collector functions locally with mocked operating system access."""
import json
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from test_scope_regressions import inventory

from ansible_state.inventory import COLLECTOR, collect


def collector(domain):
    ns = {"__name__": "collector_test"}
    exec(compile(COLLECTOR, "collector.py", "exec"), ns)  # noqa: S102 - trusted in-repo collector under test
    ns["DOMAIN"] = domain
    ns["COLLECTION"][domain] = {"scope": {"uid": 1000}, "complete": True}
    return ns


def process(stdout="", stderr="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=returncode)


@pytest.mark.parametrize("owner,uid", [("root", 0), ("alice", 1000)])
@pytest.mark.parametrize("missing", [True, False])
def test_cron_records_actual_owner(monkeypatch, owner, uid, missing):
    ns = collector("cron")
    monkeypatch.setattr(ns["pwd"], "getpwuid", lambda uid: SimpleNamespace(pw_name=owner))
    monkeypatch.setattr(ns["os"], "geteuid", lambda: uid)
    monkeypatch.setattr(ns["shutil"], "which", lambda cmd: cmd)
    result = process(stderr=f"no crontab for {owner}", returncode=1) if missing else process("job\n")
    monkeypatch.setattr(ns["subprocess"], "run", lambda *a, **kw: result)
    assert ns["cron"]() == {owner: "" if missing else "job\n"}
    assert ns["COLLECTION"]["cron"] == {"scope": {"owner": owner}, "complete": True}


def test_inaccessible_cron_not_empty(monkeypatch):
    ns = collector("cron")
    monkeypatch.setattr(ns["shutil"], "which", lambda cmd: cmd)
    monkeypatch.setattr(ns["subprocess"], "run", lambda *a, **kw: process(stderr="permission denied", returncode=1))
    assert ns["cron"]() is None
    assert not ns["COLLECTION"]["cron"]["complete"]


def test_sysctl_preserves_partial_stdout_and_failure(monkeypatch):
    ns = collector("sysctl")
    monkeypatch.setattr(ns["subprocess"], "run", lambda *a, **kw: process(
        "net.ipv4.ip_forward = 1\n", "permission denied", 1))
    assert ns["sysctl"]() == {"net.ipv4.ip_forward": "1"}
    meta = ns["COLLECTION"]["sysctl"]
    assert not meta["complete"] and meta["errors"][0]["returncode"] == 1


@pytest.mark.parametrize("domain,function", [("firewall", "firewall"), ("containers", "containers")])
def test_denied_access_differs_from_successful_empty_collection(monkeypatch, domain, function):
    ns = collector(domain)
    monkeypatch.setattr(ns["shutil"], "which", lambda cmd: cmd)
    run = Mock(return_value=process(stderr="permission denied", returncode=1))
    monkeypatch.setattr(ns["subprocess"], "run", run)
    assert ns[function]() is None
    assert ns["COLLECTION"][domain]["errors"][0]["error"] == "permission denied"
    ns["COLLECTION"][domain] = {"scope": {"uid": 1000}, "complete": True}
    run.return_value = process('{"nftables": []}' if domain == "firewall" else "")
    assert ns[function]() == ({"nftables": {"nftables": []}} if domain == "firewall" else {})
    assert ns["COLLECTION"][domain]["complete"]


def test_filesystem_permission_error_keeps_metadata_and_diagnostic(monkeypatch):
    ns = collector("filesystem")
    st = SimpleNamespace(st_dev=1, st_mode=stat.S_IFREG | 0o600, st_uid=0, st_gid=0, st_size=1)
    monkeypatch.setattr(ns["os"], "lstat", lambda path: st)

    def walk(root, **kwargs):
        kwargs["onerror"](PermissionError(13, "denied", root + "/private"))
        return [(root, [], ["file"])]

    monkeypatch.setattr(ns["os"], "walk", walk)
    ns["open"] = Mock(side_effect=PermissionError("denied"))
    result = ns["filesystem"]()
    assert result["/etc/file"]["mode"] == "0o600"
    assert "sha256" not in result["/etc/file"]
    assert not ns["COLLECTION"]["filesystem"]["complete"]
    assert any(e["resource"] == "/etc/private" for e in ns["COLLECTION"]["filesystem"]["errors"])


def event(host, status="ok", uid=0, error=None):
    return {"host": host, "status": status, "error": error,
            "inventory": json.dumps(inventory("sysctl", {}, uid=uid)) if status == "ok" else ""}


@pytest.mark.parametrize("fallback_ok", [True, False])
@pytest.mark.parametrize("unreachable", [True, False])
def test_privileged_fallback_combines_host_results(monkeypatch, fallback_ok, unreachable):
    calls = []

    def invoke(cmd, env):
        play = json.loads(Path(cmd[-1]).read_text())
        calls.append(play[0])
        if len(calls) == 1:
            events = [event("good"), event("retry", "failed", error="sudo: a password is required")]
            if unreachable:
                events.append(event("offline", "unreachable", error="connection refused"))
        else:
            assert play[0]["hosts"] == ["retry"]
            assert play[0]["tasks"][0]["become"] is False
            events = [event("retry", uid=1000)] if fallback_ok else [event("retry", "failed", error="failed")]
        Path(env["ANSIBLE_STATE_EVENTS"]).write_text("\n".join(json.dumps(e) for e in events))
        return (4 if unreachable else 2) if len(calls) == 1 else (0 if fallback_ok else 2)

    monkeypatch.setattr("ansible_state.inventory.subprocess.call", invoke)
    status, result = collect("all", ["--collector-become", "-i", "inventory.ini"])
    assert len(calls) == 2
    assert status == (0 if fallback_ok and not unreachable else 3)
    assert result["good"]["_collection"]["sysctl"]["scope"] == {"uid": 0}
    assert ("retry" in result) == fallback_ok
    if fallback_ok:
        assert result["retry"]["_collection"]["sysctl"]["scope"] == {"uid": 1000}


@pytest.mark.parametrize("status,error", [("unreachable", "connection refused"), ("failed", "script error")])
def test_nonprivilege_failures_not_retried(monkeypatch, status, error):
    def invoke(cmd, env):
        Path(env["ANSIBLE_STATE_EVENTS"]).write_text(json.dumps(event("host", status, error=error)))
        return 4

    run = Mock(side_effect=invoke)
    monkeypatch.setattr("ansible_state.inventory.subprocess.call", run)
    assert collect("all", ["--collector-become"]) == (2, {})
    assert run.call_count == 1


def test_expected_host_without_callback_is_not_success(monkeypatch):
    def invoke(cmd, env):
        Path(env["ANSIBLE_STATE_EVENTS"]).write_text(json.dumps(event("good")))
        return 0

    monkeypatch.setattr("ansible_state.inventory.subprocess.call", invoke)
    status, result = collect("all", fallback_hosts=["good", "missing"])
    assert status == 3 and set(result) == {"good"}


def test_unexplained_ansible_failure_remains_incomplete(monkeypatch):
    from ansible_state.baseline import diff

    def invoke(cmd, env):
        Path(env["ANSIBLE_STATE_EVENTS"]).write_text(json.dumps(event("good")))
        return 1

    monkeypatch.setattr("ansible_state.inventory.subprocess.call", invoke)
    status, result = collect("all")
    assert status == 3
    assert any(c["reason"] == "collection_execution_failed"
               for c in diff(result["good"], result["good"]))
