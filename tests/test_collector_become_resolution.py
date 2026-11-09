from unittest.mock import patch

from ansible_state.multi_host import resolve_hosts


def test_collector_become_is_not_forwarded_to_ansible_list_hosts():
    with patch("ansible_state.multi_host.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stdout = "  hosts (1):\n    example\n"
        result = resolve_hosts("all", ["--collector-become", "-i", "hosts.ini"])
    assert result == ["example"]
    assert run.call_args.args[0] == [
        "ansible", "all", "--list-hosts", "-i", "hosts.ini"
    ]
