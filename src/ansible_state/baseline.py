"""Immutable snapshots and explicitly approved host baselines."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid


class BaselineStore:
    def __init__(self, directory: str | Path):
        self.root = Path(directory)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _host_key(host: str) -> str:
        return hashlib.sha256(host.encode()).hexdigest()[:24]

    def _host_dir(self, host: str) -> Path:
        folder = self.root / self._host_key(host)
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def snapshot(self, host: str, data: dict) -> str:
        snapshot_id = uuid.uuid4().hex
        record = {"host": host, "created_at": datetime.now(timezone.utc).isoformat(),
                  "inventory": data}
        path = self._host_dir(host) / f"{snapshot_id}.json"
        path.write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8")
        return snapshot_id

    def snapshot_record(self, host: str, snapshot_id: str) -> dict:
        if not (isinstance(snapshot_id, str) and len(snapshot_id) == 32 and
                all(c in "0123456789abcdef" for c in snapshot_id)):
            raise ValueError("Invalid snapshot id")
        record = json.loads((self._host_dir(host) / f"{snapshot_id}.json").read_text(encoding="utf-8"))
        if record.get("host") != host or not isinstance(record.get("inventory"), dict):
            raise ValueError("Snapshot host or inventory mismatch")
        return {"snapshot_id": snapshot_id, **record}

    def latest(self, host: str) -> dict:
        folder = self._host_dir(host)
        records = []
        for path in folder.glob("*.json"):
            if path.name == "approved.json":
                continue
            try:
                record = self.snapshot_record(host, path.stem)
                records.append(record)
            except (OSError, ValueError, KeyError):
                continue
        if not records:
            raise FileNotFoundError(f"No snapshots for {host}")
        return max(records, key=lambda item: (item["created_at"], item["snapshot_id"]))

    def approve(self, host: str, snapshot_id: str) -> None:
        if not (len(snapshot_id) == 32 and all(c in "0123456789abcdef" for c in snapshot_id)):
            raise ValueError("Invalid snapshot id")
        folder = self._host_dir(host)
        path = folder / f"{snapshot_id}.json"
        self.snapshot_record(host, snapshot_id)
        pointer = folder / "approved.json"
        temporary = folder / "approved.json.tmp"
        temporary.write_text(json.dumps({"snapshot_id": snapshot_id}), encoding="utf-8")
        temporary.replace(pointer)

    def approved(self, host: str) -> dict:
        folder = self._host_dir(host)
        pointer = json.loads((folder / "approved.json").read_text(encoding="utf-8"))
        return json.loads((folder / f'{pointer["snapshot_id"]}.json').read_text(encoding="utf-8"))

    def hosts(self) -> list[str]:
        found = []
        for path in self.root.glob("*/approved.json"):
            try:
                pointer = json.loads(path.read_text(encoding="utf-8"))
                record = json.loads((path.parent / f'{pointer["snapshot_id"]}.json').read_text(encoding="utf-8"))
                found.append(record["host"])
            except (OSError, ValueError, KeyError):
                continue
        return sorted(found)


def diff(expected: dict, actual: dict) -> list[dict]:
    """Compare logical inventory domains; unknown data is never 'clean'."""
    changes = []
    for domain in ("packages", "services", "listeners", "users", "filesystem", "cron", "timers", "sysctl", "firewall", "containers"):
        old, new = expected.get(domain), actual.get(domain)
        if old is None or new is None:
            changes.append({"domain": domain, "change": "unknown"})
            continue
        if isinstance(old, list) and isinstance(new, list):
            old, new = {str(v): True for v in old}, {str(v): True for v in new}
        for key in sorted(old.keys() | new.keys()):
            if key not in old:
                changes.append({"domain": domain, "resource": key, "change": "added",
                                "current": new[key]})
            elif key not in new:
                changes.append({"domain": domain, "resource": key, "change": "removed",
                                "baseline": old[key]})
            elif old[key] != new[key]:
                changes.append({"domain": domain, "resource": key, "change": "modified",
                                "baseline": old[key], "current": new[key]})
    return changes
