from ansible_state.baseline import diff
from ansible_state.inventory import COLLECTOR


def test_collector_syntax():
    compile(COLLECTOR, "collector.py", "exec")


def test_volatile_sysctl_not_reported():
    expected = {"sysctl": {"kernel.random.uuid": "a", "fs.file-nr": "1", "net.ipv4.ip_forward": "1"}}
    actual = {"sysctl": {"kernel.random.uuid": "b", "fs.file-nr": "2", "net.ipv4.ip_forward": "1"}}
    assert not [x for x in diff(expected, actual) if x["domain"] == "sysctl"]


def test_docker_uptime_ignored_across_schema():
    expected = {"containers": {"app": {"image": "app:1", "status": "Up 2 hours"}}}
    actual = {"containers": {"app": {"image": "app:1", "state": "running"}}}
    assert not [x for x in diff(expected, actual) if x["domain"] == "containers"]


def test_docker_state_change_detected():
    expected = {"containers": {"app": {"image": "app:1", "status": "Exited (0) 2 days ago"}}}
    actual = {"containers": {"app": {"image": "app:1", "state": "running"}}}
    assert any(x["domain"] == "containers" and x["change"] == "modified"
               for x in diff(expected, actual))
