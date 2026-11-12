"""Conservative baseline backfill: never replace known historical values."""
from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime

from ansible_state.baseline import DOMAINS, BaselineStore, diff, domain_metadata
from ansible_state.classification import apply_policy


def plan_backfill(store: BaselineStore, host: str, current: dict) -> dict:
    """Fill only absent, reliably collected domains; retain historical provenance."""
    approved = store.approved(host)
    old = approved["inventory"]
    merged = deepcopy(old)
    added, unavailable = [], []
    for domain in DOMAINS:
        if old.get(domain) is not None:
            continue
        value = current.get(domain)
        meta = domain_metadata(current, domain)
        # No scope/completeness metadata means reliability cannot be established.
        if (value is None or meta.get("complete") is not True or
                not meta.get("scope") or current.get("_execution_error")):
            unavailable.append(domain)
            continue
        merged[domain] = deepcopy(value)
        merged.setdefault("_collection", {})[domain] = deepcopy(meta)
        # Remove inherited failure markers only for domains being replaced.
        merged.get("_collection_errors", {}).pop(domain, None)
        if domain in merged.get("_partial_domains", []):
            merged["_partial_domains"].remove(domain)
        merged.setdefault("_provenance", {})[domain] = {
            "method": "backfill", "source_snapshot_id": approved["snapshot_id"],
            "scope": deepcopy(meta["scope"]),
            "collected_at": current.get("_collected_at"),
            "backfilled_at": datetime.now(UTC).isoformat(),
        }
        added.append(domain)
    observations = apply_policy(diff(old, current), [])
    known_changes = [c for c in observations if c["change"] != "unknown"]
    unresolved = [c for c in observations if c["change"] == "unknown" and
                  c["domain"] not in added]
    review = {"source_snapshot_id": approved["snapshot_id"],
              "existing_changes": known_changes, "unresolved": unresolved,
              "requires_acknowledgement": bool(known_changes or unresolved)}
    merged["_migration"] = review
    return {"host": host, "source_snapshot_id": approved["snapshot_id"],
            "inventory": merged, "backfilled": added,
            "still_unavailable": unavailable,
            "existing_changes": known_changes, "unresolved": unresolved,
            "requires_acknowledgement": review["requires_acknowledgement"]}
