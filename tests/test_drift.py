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
