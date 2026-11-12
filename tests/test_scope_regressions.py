"""Visibility changes are observations, not configuration changes."""
from copy import deepcopy

import pytest

from ansible_state.baseline import DOMAINS, diff
from ansible_state.classification import apply_policy


def inventory(domain, values, uid=0, complete=True):
    result = {name: {} for name in DOMAINS}
    result[domain] = values
    result["_collection"] = {domain: {"scope": {"uid": uid}, "complete": complete}}
    return result


def changes(old, new, domain):
    return [c for c in diff(old, new) if c["domain"] == domain]


@pytest.mark.parametrize("domain", ["filesystem", "sysctl", "firewall", "containers"])
@pytest.mark.parametrize("uids", [(0, 1000), (1000, 0)])
def test_privilege_change_does_not_confirm_membership_changes(domain, uids):
    old = inventory(domain, {"old": "1"}, uid=uids[0])
    new = inventory(domain, {"new": "1"}, uid=uids[1])
    found = changes(old, new, domain)
    assert found and all(c["change"] == "unknown" for c in found)
    assert any(c["reason"] == "collection_scope_changed" for c in found)


@pytest.mark.parametrize("domain", ["filesystem", "sysctl"])
def test_common_observations_still_detect_changes_across_privileges(domain):
    old = inventory(domain, {"readable": "1"}, uid=1000)
    new = inventory(domain, {"readable": "2", "newly-visible": "1"})
    found = changes(old, new, domain)
    assert any(c["change"] == "modified" and c["resource"] == "readable" for c in found)
    assert not any(c["change"] == "added" for c in found)


@pytest.mark.parametrize("domain", ["sysctl", "filesystem"])
def test_partial_collections_preserve_modifications_without_deletions(domain):
    old = inventory(domain, {"readable": "1", "hidden": "1"})
    new = inventory(domain, {"readable": "2"}, complete=False)
    new["_collection"][domain]["errors"] = [{"error": "permission denied"}]
    found = changes(old, new, domain)
    assert any(c["change"] == "modified" for c in found)
    assert not any(c["change"] == "removed" for c in found)
    assert any(c.get("collector_error") for c in found)
    assert any(c["reason"] == "collection_partial" for c in found)


def test_partial_baseline_does_not_confirm_new_visibility_as_addition():
    old = inventory("sysctl", {"a": "1"}, complete=False)
    new = inventory("sysctl", {"a": "2", "b": "1"})
    found = changes(old, new, "sysctl")
    assert not any(c["change"] == "added" for c in found)
    assert any(c["change"] == "modified" for c in found)


def test_filesystem_unreadable_hash_preserves_observed_mode_change():
    old = inventory("filesystem", {"/etc/a": {"type": "file", "mode": "0o600", "sha256": "a"}})
    new = inventory("filesystem", {"/etc/a": {"type": "file", "mode": "0o644"}}, complete=False)
    found = changes(old, new, "filesystem")
    assert {c["change"] for c in found} == {"unknown", "modified"}
    new["filesystem"]["/etc/a"] = {"type": "unreadable"}
    assert all(c["change"] == "unknown" for c in changes(old, new, "filesystem"))


def test_complete_same_scope_detects_all_resource_changes():
    old = inventory("filesystem", {"a": "1", "removed": "1"})
    new = inventory("filesystem", {"a": "2", "added": "1"})
    assert {c["change"] for c in changes(old, new, "filesystem")} == {"added", "removed", "modified"}


def test_cron_owners_are_distinct_and_legacy_owner_is_unknown():
    old = inventory("cron", {"alice": "job1"})
    old["_collection"]["cron"]["scope"] = {"owner": "alice"}
    new = inventory("cron", {"root": "job2"})
    new["_collection"]["cron"]["scope"] = {"owner": "root"}
    assert all(c["change"] == "unknown" for c in changes(old, new, "cron"))
    legacy = {"cron": {"current_user": "job1"}}
    assert changes(legacy, new, "cron")[0]["reason"] == "legacy_cron_owner_unknown"
    old["cron"]["alice"] = "job2"
    previous = deepcopy(old)
    previous["cron"]["alice"] = "job1"
    assert changes(previous, old, "cron")[0]["change"] == "modified"


def test_legacy_values_comparable_but_absence_has_unknown_visibility():
    old = {"sysctl": {"a": "1", "hidden": "1"}}
    new = {"sysctl": {"a": "2"}}
    found = changes(old, new, "sysctl")
    assert any(c["change"] == "modified" for c in found)
    assert not any(c["change"] == "removed" for c in found)


def test_policy_cannot_hide_collection_failures():
    findings = apply_policy([
        {"domain": "firewall", "change": "unknown", "reason": "collection_unavailable"},
        {"domain": "firewall", "change": "modified", "resource": "ruleset"},
    ], [{"domain": "*"}])
    assert len(findings) == 1 and findings[0]["change"] == "unknown"


def test_docker_state_only_is_runtime_image_change_is_configuration():
    before = {"image": "app:1", "state": "running"}
    for after, category in [({"image": "app:1", "state": "exited"}, "runtime"),
                            ({"image": "app:2", "state": "running"}, "configuration")]:
        result = apply_policy([{"domain": "containers", "change": "modified",
                                "baseline": before, "current": after}], [])
        assert result[0]["category"] == category


def test_legacy_partial_markers_remain_supported():
    old = {"sysctl": {"hidden": "1"}}
    new = {"sysctl": {}, "_partial_domains": ["sysctl"],
           "_collection_errors": {"sysctl": {"error": "denied"}}}
    found = changes(old, new, "sysctl")
    assert all(c["change"] == "unknown" for c in found)
    assert any(c.get("collector_error") for c in found)


def test_legacy_root_cron_has_known_owner():
    old = {"_collector_scope": "root", "cron": {"current_user": "job1"}}
    new = inventory("cron", {"root": "job2"})
    new["_collection"]["cron"]["scope"] = {"owner": "root"}
    found = changes(old, new, "cron")
    assert len(found) == 1 and found[0]["change"] == "modified"
    assert found[0]["resource"] == "root"


def test_mount_boundary_changes_cannot_prove_deletions():
    old = inventory("filesystem", {"/etc/mount/file": {"type": "file", "sha256": "a"}})
    old["_collection"]["filesystem"]["scope"]["excluded_mounts"] = []
    new = inventory("filesystem", {})
    new["_collection"]["filesystem"]["scope"]["excluded_mounts"] = ["/etc/mount"]
    found = changes(old, new, "filesystem")
    assert found and all(c["change"] == "unknown" for c in found)
