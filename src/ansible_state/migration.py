"""Conservative baseline backfill: never replace known historical values."""
from __future__ import annotations

from ansible_state.baseline import BaselineStore, diff

DOMAINS = ("packages", "services", "listeners", "users", "filesystem",
           "cron", "timers", "sysctl", "firewall", "containers")


def plan_backfill(store: BaselineStore, host: str, current: dict) -> dict:
    """Prepare a candidate using only fields missing from the approved snapshot.

    The approved pointer is never changed here. Existing values are immutable.
    """
    approved = store.approved(host)
    old = approved["inventory"]
    merged = dict(old)
    added = []
    unavailable = []
    for domain in DOMAINS:
        if old.get(domain) is not None:
            continue
        value = current.get(domain)
        if value is None:
            unavailable.append(domain)
        else:
            merged[domain] = value
            added.append(domain)
    # Detect changes to previously known fields independently of backfill.
    known_changes = [c for c in diff(old, current)
                     if c["change"] != "unknown"]
    return {"host": host, "source_snapshot_id": approved["snapshot_id"],
            "inventory": merged, "backfilled": added,
            "still_unavailable": unavailable,
            "existing_changes": known_changes}
