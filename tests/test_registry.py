import json

from ansible_state.observation import ingest
from ansible_state.state import Registry


def test_registry_upsert(tmp_path):
    db = Registry(tmp_path / "state.db")
    db.record("node", "copy", "/etc/app", "abc", {"mode": "0644"}, "run1")
    db.record("node", "copy", "/etc/app", "def", {"mode": "0600"}, "run2")
    resources = db.list_resources()
    assert len(resources) == 1
    assert resources[0]["checksum"] == "def"
    assert resources[0]["last_run"] == "run2"
    db.close()


def test_ingest_ignores_skipped_absent_and_unrelated(tmp_path):
    events = tmp_path / "events.jsonl"
    base = {"status": "ok", "host": "node", "action": "copy",
            "result": {"dest": "/etc/app", "checksum": "abc"}, "args": {}}
    rows = [base, {**base, "status": "skipped"},
            {**base, "action": "shell"},
            {**base, "args": {"state": "absent"}}]
    events.write_text("\n".join(json.dumps(row) for row in rows))
    db = Registry(tmp_path / "state.db")
    assert ingest(events, db, "run1") == 1
    assert len(db.list_resources()) == 1
    db.close()
