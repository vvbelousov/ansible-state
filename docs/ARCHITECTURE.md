# Architecture — v0.1 design

## Invariants

- Existing playbooks and roles must run unchanged with `ansible-playbook`.
- `ansible-state` is an opt-in wrapper, not an Ansible fork or YAML interpreter.
- State tracking must never silently delete resources.
- Skipped/conditional/dynamic tasks must not be treated as removed resources.
- Partial, limited, tagged or failed executions cannot authorize pruning.
- Running ordinary Ansible outside the wrapper may stale the registry; re-observe
  before any future destructive operation.

## Components (planned)

1. CLI/runner: forwards execution to ansible-core without changing playbook semantics.
2. Observation: capture supported resource operations and post-run state.
3. Registry: SQLite mapping of host, resource identity, ownership, observed state,
   run completeness and source provenance.
4. Planner: three-way comparison (previous managed, current observed, desired).
5. Adapters: initially file/copy/template; unknown modules remain opaque.
6. Executor: future guarded apply, never automatic in v0.1.

## Identity and ownership

Do not use task display names as resource IDs. Prefer a canonical host, resource
kind and resource address, with provenance as additional metadata. Shared ownership,
resource moves and ambiguous dynamic tasks require explicit safe behavior.

## Known limitations

Callback events alone cannot reliably determine the full desired resource set.
Ansible check mode does not provide a complete plan for arbitrary modules.
Shell/command side effects are opaque. These are design constraints, not TODOs
that can safely be bypassed.

## v0.1 acceptance

- Run an unmodified playbook and propagate exit status.
- Implement read-only observation for a narrowly supported resource type.
- Persist observed state locally in SQLite.
- Report drift without destructive changes.
- Integration tests for idempotent runs, skipped tasks and failed/partial runs.


## Inventory comparison and migration

The host-wide inventory is separate from callback-observed file ownership.
Ansible executes a temporary read-only Python script and returns JSON through the
inventory callback. Schema 2 preserves the domain mappings of schema 1 and adds
`_collection[domain] = {scope, complete, errors?}`. Identity is effective UID for
permission-sensitive inventories, actual owner for cron, and system scope for
host-wide public domains. Docker scope also includes the endpoint and context.
Errors contain resource/command/returncode when known. A partial mapping retains
observed values; missing keys in it are not proof of absence.
Each domain has an exception boundary so an unexpected collector failure does
not discard unrelated observations. Invalid domain values cannot become reliable
backfill inputs simply by claiming complete metadata.

Firewall scope also records normalization version 2. Counter removal is limited
to counter fields: iptables comments and nftables quota thresholds remain
configuration, while quota usage is excluded. Older normalization irreversibly
removed some configuration, so cross-version firewall comparisons are unknown
and require review and explicit approval of a fresh snapshot.

Comparison treats visibility separately from value equality. Additions need a
complete comparable baseline; removals need a complete comparable current scan.
Shared filesystem/sysctl observations still establish modifications during partial
collection. Missing filesystem attributes produce unknown findings while shared
attributes remain comparable. Services preserve unit-file settings if active-state
collection fails. Opaque firewall/Docker inventories with different identity scopes
remain unknown. Domain completeness and unknown resources coexist with confirmed
drift. Policy exclusions only remove confirmed changes, never unknowns.

Legacy snapshots remain immutable. Global `_collector_scope`, `_partial_domains`,
`_collection_errors` and `_backfill_provenance` are read conservatively. Domain
provenance overrides global scope. Missing legacy identities do not prove absence;
legacy `current_user` cron cannot identify an owner without supporting metadata.
The legacy `user` scope cannot prove identity even when both labels match.
Ambiguous cron entries do not prevent comparison of separately identified owners.
Execution errors in approved historical snapshots remain unknown findings.

Migration deep-copies the approved inventory and fills only wholly absent domains
from complete, explicitly scoped current observations. It retains each backfilled
domain's metadata and records `_provenance` with source baseline ID, scope and
collection time. It never replaces known historical values or scope metadata.
`_migration` stores existing changes and unresolved findings as immutable candidate
review data. Approval checks the source baseline has not changed and requires
explicit acknowledgement for candidates with warnings. All manifest entries are
validated before pointers change; approval across hosts is not transactional.

Privilege fallback targets only callback-confirmed escalation failures. The callback
also records unreachable hosts, which are not retried. Final collection outcomes
combine successful privileged and fallback inventories with unrecovered hosts:
0 complete, 3 partial, 2 total failure, 127 executable unavailable. Ansible inventory
resolution supplies expected hosts so absent callback events cannot count as success.
Actual identities are collected on the target even after fallback.
Fallback results are accepted only for the requested retry hosts and cannot
replace an earlier successful privileged observation. Migration forwards ordinary
Ansible connection options through the same resolution and collection paths.

Classification distinguishes configuration drift, runtime changes and incomplete
observations. A host with confirmed configuration changes is DRIFT even if incomplete;
otherwise unresolved observations imply INCOMPLETE, and runtime-only changes can be
OK. These facts remain separate in JSON flags and text summary counters. See the
README for scope boundaries, CLI examples and migration approval behavior.
