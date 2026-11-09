from ansible_state.drift import compare


def test_missing_file():
    assert compare({"checksum": "abc", "attributes": {}}, {"exists": False}) == ["missing"]


def test_changed_checksum_and_mode():
    expected = {"checksum": "abc", "attributes": {"mode": "0644"}}
    actual = {"exists": True, "checksum": "def", "mode": "0600"}
    assert compare(expected, actual) == ["checksum", "mode"]


def test_unknown_checksum_not_reported():
    expected = {"checksum": None, "attributes": {"owner": "root"}}
    assert compare(expected, {"exists": True, "owner": "root"}) == []

def test_stat_uses_posix_owner_group_names():
    expected = {"checksum": None, "attributes": {"owner": "root", "group": "root"}}
    actual = {"exists": True, "pw_name": "root", "gr_name": "root"}
    assert compare(expected, actual) == []


def test_stat_detects_real_owner_group_change():
    expected = {"checksum": None, "attributes": {"owner": "root", "group": "root"}}
    actual = {"exists": True, "pw_name": "nobody", "gr_name": "nogroup"}
    assert compare(expected, actual) == ["owner", "group"]
