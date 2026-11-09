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
