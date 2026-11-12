from unittest.mock import patch

from ansible_state.cli import main


def test_apply_passes_arguments_unchanged(tmp_path):
    with (
        patch("sys.argv", ["ansible-state", "apply", "-i", "inventory", "site.yml", "--check"]),
        patch.dict("os.environ", {"ANSIBLE_STATE_DB": str(tmp_path / "state.db")}, clear=True),
        patch("subprocess.call", return_value=7) as run,
    ):
        assert main() == 7
    assert run.call_args.args[0] == [
        "ansible-playbook", "-i", "inventory", "site.yml", "--check"
    ]
    assert run.call_args.kwargs["env"]["ANSIBLE_CALLBACKS_ENABLED"] == "state_events"


def test_apply_preserves_existing_callbacks():
    with (
        patch("sys.argv", ["ansible-state", "apply", "site.yml"]),
        patch.dict("os.environ", {"ANSIBLE_CALLBACKS_ENABLED": "custom"}, clear=True),
        patch("subprocess.call", return_value=0) as run,
    ):
        assert main() == 0
    run.assert_called_once_with(["ansible-playbook", "site.yml"])
