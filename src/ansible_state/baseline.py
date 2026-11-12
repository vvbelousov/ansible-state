"""Immutable snapshots and explicitly approved host baselines."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path


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
        record = {"host": host, "created_at": datetime.now(UTC).isoformat(),
                  "inventory": data}
        path = self._host_dir(host) / f"{snapshot_id}.json"
        path.write_text(json.dumps(record, sort_keys=True, indent=2), encoding="utf-8")
        return snapshot_id

    def snapshot_record(self, host: str, snapshot_id: str) -> dict:
        if not (isinstance(snapshot_id, str) and len(snapshot_id) == 32 and
                all(c in "0123456789abcdef" for c in snapshot_id)):
            raise ValueError("Invalid snapshot id")
        record = json.loads((self._host_dir(host) / f"{snapshot_id}.json").read_text(encoding="utf-8"))
        if (not isinstance(record, dict) or record.get("host") != host or
                not isinstance(record.get("inventory"), dict)):
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

    def validate_approval(self, host: str, snapshot_id: str,
                          accept_migration_warnings: bool = False) -> None:
        migration = self.snapshot_record(host, snapshot_id)["inventory"].get("_migration")
        if not migration:
            return
        if self.approved(host)["snapshot_id"] not in (snapshot_id, migration["source_snapshot_id"]):
            raise ValueError("Migration source baseline changed; prepare a fresh candidate")
        if migration.get("requires_acknowledgement") and not accept_migration_warnings:
            raise ValueError("Migration contains existing changes or unresolved observations; "
                             "review the candidate and pass --accept-migration-warnings")

    def approve(self, host: str, snapshot_id: str,
                accept_migration_warnings: bool = False) -> None:
        if not (len(snapshot_id) == 32 and all(c in "0123456789abcdef" for c in snapshot_id)):
            raise ValueError("Invalid snapshot id")
        folder = self._host_dir(host)
        self.validate_approval(host, snapshot_id, accept_migration_warnings)
        pointer = folder / "approved.json"
        temporary = folder / "approved.json.tmp"
        temporary.write_text(json.dumps({"snapshot_id": snapshot_id}), encoding="utf-8")
        temporary.replace(pointer)

    def approved(self, host: str) -> dict:
        folder = self._host_dir(host)
        pointer = json.loads((folder / "approved.json").read_text(encoding="utf-8"))
        return self.snapshot_record(host, pointer["snapshot_id"])

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


DOMAINS = ("packages", "services", "listeners", "users", "filesystem",
           "cron", "timers", "sysctl", "firewall", "containers")
SCOPED_DOMAINS = {"filesystem", "cron", "sysctl", "firewall", "containers"}


def domain_metadata(inventory: dict, domain: str) -> dict:
    """Read current metadata and the earlier partial/error markers conservatively."""
    meta = dict(inventory.get("_collection", {}).get(domain, {}))
    errors = inventory.get("_collection_errors", {}).get(domain)
    if errors:
        meta.setdefault("errors", errors)
    if (inventory.get(domain) is None or errors or meta.get("errors") or
            domain in inventory.get("_partial_domains", [])):
        meta["complete"] = False
    provenance = inventory.get("_provenance", {}).get(domain, {})
    if "scope" not in meta and provenance.get("scope"):
        meta["scope"] = provenance["scope"]
    legacy_provenance = inventory.get("_backfill_provenance", {}).get(domain, {})
    legacy_scope = legacy_provenance.get("collector_scope", inventory.get("_collector_scope"))
    if "scope" not in meta and legacy_scope and domain in SCOPED_DOMAINS:
        if domain == "cron" and legacy_scope == "root":
            meta["scope"] = {"owner": "root"}
        elif domain != "cron":
            meta["scope"] = {"uid": 0} if legacy_scope == "root" else {"legacy_user": True}
    return meta


def _containers(items: dict) -> dict:
    states = {"up": "running"}
    result = {}
    for key, value in items.items():
        if isinstance(value, dict):
            state = str(value.get("status", "")).split(" ", 1)[0].lower()
            value = {"image": value.get("image"),
                     "state": value.get("state", states.get(state, state))}
        result[key] = value
    return result


def diff(expected: dict, actual: dict) -> list[dict]:
    """Compare observed values; absence is evidence only in complete, equal scopes.

    Legacy values remain comparable, but legacy visibility is unknown for
    permission-sensitive domains. In particular, current_user has no safe owner.
    """
    from ansible_state.inventory import VOLATILE_SYSCTL_KEYS

    changes = []
    if actual.get("_execution_error"):
        changes.append({"domain": "_execution", "change": "unknown",
                        "reason": "collection_execution_failed",
                        "collector_error": actual["_execution_error"]})
    for domain in DOMAINS:
        old, new = expected.get(domain), actual.get(domain)
        before = domain_metadata(expected, domain)
        after = domain_metadata(actual, domain)

        def unknown(reason, resource=None, domain=domain, before=before, after=after):
            item = {"domain": domain, "change": "unknown", "reason": reason}
            if resource is not None:
                item["resource"] = resource
            if reason in {"collection_scope_changed", "legacy_scope_unknown"}:
                item["baseline_scope"] = before.get("scope")
                item["current_scope"] = after.get("scope")
            if before.get("errors"):
                item["baseline_error"] = before["errors"]
            if after.get("errors"):
                item["collector_error"] = after["errors"]
            changes.append(item)

        if old is None or new is None:
            unknown("collection_unavailable" if new is None and old is not None
                    else "baseline_unavailable")
            if old is None and new is None:
                changes[-1]["collection_unavailable"] = True
            continue
        if isinstance(old, list) and isinstance(new, list):
            old, new = {str(v): True for v in old}, {str(v): True for v in new}
        if not isinstance(old, dict) or not isinstance(new, dict):
            unknown("invalid_domain_data")
            continue
        old, new = dict(old), dict(new)
        if domain == "cron":
            legacy_owner_unknown = False
            for values, meta in ((old, before), (new, after)):
                if "current_user" in values:
                    owner = meta.get("scope", {}).get("owner")
                    if owner:
                        values[owner] = values.pop("current_user")
                    else:
                        legacy_owner_unknown = True
            if legacy_owner_unknown:
                unknown("legacy_cron_owner_unknown")
                continue
        if domain == "sysctl":
            old = {k: v for k, v in old.items() if k not in VOLATILE_SYSCTL_KEYS}
            new = {k: v for k, v in new.items() if k not in VOLATILE_SYSCTL_KEYS}
        if domain == "containers":
            old, new = _containers(old), _containers(new)
        scoped = domain in SCOPED_DOMAINS
        scopes_known = before.get("scope") is not None and after.get("scope") is not None
        same_scope = not scoped or (scopes_known and before["scope"] == after["scope"])
        if scoped and not same_scope and (scopes_known or before.get("scope") or
                                         after.get("scope") or old.keys() != new.keys()):
            unknown("collection_scope_changed" if scopes_known else "legacy_scope_unknown")
        if before.get("complete") is False:
            unknown("baseline_partial")
        if after.get("complete") is False:
            unknown("collection_partial")
        # Docker names can refer to different daemons; firewall is an opaque ruleset.
        if (domain in {"containers", "firewall"} and not same_scope and
                (before.get("scope") or after.get("scope"))):
            continue
        for key in sorted(old.keys() | new.keys()):
            if key not in old:
                if same_scope and before.get("complete", True):
                    changes.append({"domain": domain, "resource": key, "change": "added",
                                    "current": new[key]})
                else:
                    unknown("baseline_visibility_unknown", key)
            elif key not in new:
                if same_scope and after.get("complete", True):
                    changes.append({"domain": domain, "resource": key, "change": "removed",
                                    "baseline": old[key]})
                else:
                    unknown("current_visibility_unknown", key)
            else:
                left, right = old[key], new[key]
                if domain in {"filesystem", "services"} and isinstance(left, dict) and isinstance(right, dict):
                    if left.get("type") == "unreadable" or right.get("type") == "unreadable":
                        unknown("resource_unreadable", key)
                        continue
                    if left.keys() != right.keys():
                        unknown("resource_attributes_unavailable", key)
                        common = left.keys() & right.keys()
                        left = {k: left[k] for k in common}
                        right = {k: right[k] for k in common}
                if left != right:
                    changes.append({"domain": domain, "resource": key, "change": "modified",
                                    "baseline": left, "current": right})
    return changes
