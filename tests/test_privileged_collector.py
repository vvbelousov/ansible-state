from ansible_state.baseline import diff
from ansible_state.inventory import COLLECTOR, VOLATILE_SYSCTL_KEYS


def test_quota_syncs_are_not_configuration_drift():
    expected = {"sysctl": {"fs.quota.syncs": "256", "net.ipv4.ip_forward": "0"}}
    current = {"sysctl": {"fs.quota.syncs": "258", "net.ipv4.ip_forward": "0"}}
    assert not [change for change in diff(expected, current) if change["domain"] == "sysctl"]
    assert "fs.quota.syncs" in VOLATILE_SYSCTL_KEYS


def test_collector_script_compiles():
    compile(COLLECTOR, "collector.py", "exec")
