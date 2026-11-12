import json
from pathlib import Path
from unittest.mock import patch

from ansible_state.inventory import collect


def test_privileged_collection_retries_only_failed_hosts(tmp_path):
    calls = []

    def fake_call(cmd, env):
        calls.append(cmd)
        events = Path(env["ANSIBLE_STATE_EVENTS"])
        playbook = json.loads(Path(cmd[-1]).read_text())
        if playbook[0]["tasks"][0]["become"]:
            events.write_text(
                json.dumps({"host": "denied", "status": "failed", "error": "sudo: a password is required"}) + "\n"
                + json.dumps({"host": "offline", "status": "unreachable"}) + "\n"
                + json.dumps({"host": "ok", "status": "ok",
                              "inventory": json.dumps({"_collector_scope": "root"})}) + "\n"
            )
            return 2
        assert playbook[0]["hosts"] == ["denied"]
        events.write_text(json.dumps({
            "host": "denied", "status": "ok",
            "inventory": json.dumps({"_collector_scope": "user"})
        }) + "\n")
        return 0

    with patch("ansible_state.inventory.subprocess.call", side_effect=fake_call):
        status, result = collect("all", ["--collector-become"],
                                 fallback_hosts=["denied", "offline", "ok"])
    assert status == 3
    assert len(calls) == 2
    assert result["ok"]["_collector_scope"] == "root"
    assert result["denied"]["_collector_scope"] == "user"
    assert "offline" not in result
