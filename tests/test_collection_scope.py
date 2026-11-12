from ansible_state.baseline import diff


def changes_for(expected, actual, domain):
    return [c for c in diff(expected, actual) if c["domain"] == domain]


def test_unreadable_to_hash_is_unknown_not_modified():
    old = {"filesystem": {"/etc/shadow": {"type": "unreadable"}}}
    new = {"filesystem": {"/etc/shadow": {"type": "file", "sha256": "abc"}}}
    changes = changes_for(old, new, "filesystem")
    assert len(changes) == 1
    assert changes[0]["change"] == "unknown"
    assert changes[0]["reason"] == "resource_unreadable"


def test_root_scope_additions_are_unknown():
    old = {"sysctl": {"net.ipv4.ip_forward": "0"}}
    new = {"_collector_scope": "root", "sysctl": {
        "net.ipv4.ip_forward": "0", "vm.mmap_rnd_bits": "28"}}
    changes = changes_for(old, new, "sysctl")
    assert changes and all(c["change"] == "unknown" for c in changes)
    assert any(c["resource"] == "vm.mmap_rnd_bits" for c in changes if "resource" in c)


def test_real_known_change_still_detected_across_scopes():
    old = {"filesystem": {"/etc/ssh/sshd_config": {
        "type": "file", "sha256": "old"}}}
    new = {"_collector_scope": "root", "filesystem": {
        "/etc/ssh/sshd_config": {"type": "file", "sha256": "new"}}}
    changes = changes_for(old, new, "filesystem")
    assert any(c["change"] == "modified" for c in changes)


def test_legacy_user_scope_does_not_prove_privilege_or_completeness():
    old = {"sysctl": {"net.ipv4.ip_forward": "0"}}
    new = {"_collector_scope": "user", "sysctl": {
        "net.ipv4.ip_forward": "0", "net.ipv4.tcp_syncookies": "1"}}
    changes = changes_for(old, new, "sysctl")
    assert changes and all(c["change"] == "unknown" for c in changes)


def test_partial_sysctl_does_not_report_missing_as_removed():
    old = {"sysctl": {"net.ipv4.ip_forward": "0", "kernel.some_key": "1"}}
    new = {"_partial_domains": ["sysctl"],
           "sysctl": {"net.ipv4.ip_forward": "0"}}
    changes = changes_for(old, new, "sysctl")
    assert changes and all(c["change"] == "unknown" for c in changes)
    assert any(c["reason"] == "collection_partial" for c in changes)
