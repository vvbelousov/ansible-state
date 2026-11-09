from unittest.mock import patch

from ansible_state.cli import main


def test_apply_passes_arguments_unchanged():
    with patch("sys.argv", ["ansible-state", "apply", "-i", "inventory", "site.yml", "--check"]):
        with patch("subprocess.call", return_value=7) as run:
            assert main() == 7
    run.assert_called_once_with(
        ["ansible-playbook", "-i", "inventory", "site.yml", "--check"]
    )
