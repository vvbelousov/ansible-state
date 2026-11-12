"""Exercise the actual Ansible script/callback transport without SSH or host scans."""
import json
import shutil
import sys

import pytest
from test_scope_regressions import inventory

from ansible_state.inventory import collect


def test_local_script_callback_roundtrip(tmp_path, monkeypatch):
    if not shutil.which("ansible-playbook"):
        pytest.skip("ansible-playbook is not installed")
    hosts = tmp_path / "hosts.ini"
    hosts.write_text(f"node ansible_connection=local ansible_python_interpreter={sys.executable} "
                     f"ansible_remote_tmp={tmp_path / 'remote'}\n")
    monkeypatch.setenv("ANSIBLE_LOCAL_TEMP", str(tmp_path / "local"))
    data = inventory("sysctl", {"net.ipv4.ip_forward": "1"})
    script = "#!/usr/bin/env python3\nimport json\nprint(json.dumps(" + repr(data) + "))\n"
    monkeypatch.setattr("ansible_state.inventory.COLLECTOR", script)
    status, result = collect("all", ["-i", str(hosts)])
    assert status == 0
    assert result == {"node": data}
    # Collection creates no baseline and makes no approval decisions.
    assert not (tmp_path / "snapshots").exists()
    assert json.loads(json.dumps(result))["node"]["sysctl"] == data["sysctl"]
