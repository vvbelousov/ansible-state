# ansible-state

Experimental, opt-in read-only resource observation for **unchanged** Ansible playbooks.

> Early prototype. This is **not** a Terraform-like plan/apply engine yet.
> Read-only drift inspection is experimental; automatic cleanup is not implemented.

## Install

```bash
python -m pip install -e '.[dev]'
```

## Run

```bash
ansible-state apply -i inventory site.yml
ansible-state state
ansible-state drift -i inventory
```

`apply` executes the system `ansible-playbook` command and propagates its
exit status. Successful runs record limited file/copy/template results in
`.ansible-state/state.db`. Override this location with `ANSIBLE_STATE_DB`.

The state command prints observed resources as JSON. Use `drift` to inspect registered paths on their recorded hosts via Ansible's read-only `stat` module. It compares SHA-1 checksums (where recorded), modes and ownership. Exit codes: 0 = no detected drift, 3 = drift or unknown state, other nonzero = Ansible execution error. This is not a full filesystem or desired-state scan. Observations may be incomplete.

If `ANSIBLE_CALLBACK_PLUGINS` or `ANSIBLE_CALLBACKS_ENABLED` is already
configured, the wrapper currently runs Ansible without observation rather
than replacing the existing callback configuration.

## Safety

- Existing playbooks remain runnable directly with `ansible-playbook`.
- No resource deletion, pruning or reconciliation is implemented.
- Drift inspection reads only paths already recorded in the registry.
- Inspection requires inventory/connectivity to the recorded hosts.
- File metadata and checksums can be stale after ordinary Ansible runs.
- A failed Ansible run does not commit observations from that run.
- Arbitrary module side effects are not tracked.
- The registry is not a complete desired-state graph.
- Do not rely on the registry for recovery or compliance decisions.

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
ruff check src tests
```

See [architecture](docs/ARCHITECTURE.md).

## Host-wide inventory (experimental)

Collection runs manually through Ansible's existing inventory, connection and
configuration. Targets need Python 3 and Linux tools. No daemon, monitoring,
remediation or automatic approval is installed.

```bash
ansible-state snapshot webservers -i inventory.ini --collector-become
ansible-state baseline status webservers -i inventory.ini --write-manifest approvals.json
# Review each exact host and snapshot ID, then explicitly approve:
ansible-state baseline approve --manifest approvals.json --confirm
ansible-state system-drift webservers -i inventory.ini --collector-become --report-format text
# Single-host approval also remains available:
ansible-state baseline approve HOST SNAPSHOT_ID
```

The collector supports these domains:

| Domain | Observation |
| --- | --- |
| packages | dpkg/rpm installed versions |
| services | systemd unit-file settings and active states |
| listeners | Listening TCP/UDP endpoints, without process IDs |
| users | User names, UID/GID, home and shell |
| filesystem | Metadata and SHA-256 for regular files up to 8 MiB |
| cron | Effective user's crontab, keyed by its actual owner |
| timers | systemd timer unit-file settings |
| sysctl | Readable kernel settings; selected volatile counters excluded |
| firewall | nftables JSON, otherwise IPv4 iptables-save; runtime counters excluded |
| containers | Docker names, image references and states |

Filesystem roots are `/etc`, `/usr/local/etc`, `/usr/local/bin`, `/opt`, and
`/srv`. Symlinks are recorded without following them; different-device mounts
are skipped. Files larger than 8 MiB have metadata and size only. File contents
are never stored, but crontab text and firewall rules are stored. Protect the
local `.ansible-state/` directory. `ANSIBLE_STATE_SNAPSHOTS` overrides snapshot
storage; the file observation registry separately uses `ANSIBLE_STATE_DB`.

### Privileges and incomplete observations

Collection defaults to an unprivileged task. Use `--collector-become` to request
Ansible become; ordinary `--become` alone does not enable the collector task.
Ansible inventory variables retain their normal precedence. The recorded scope
uses the **actual effective identity**, rather than assuming become succeeded.
A privilege escalation failure triggers one unprivileged retry for that host.
Unreachable hosts and unrelated script failures are not retried. Successful
privileged inventories are retained when other hosts need fallback.

Schema 2 snapshots store `_collection` metadata per domain: `scope`, `complete`,
and structured `errors` with command, return code or resource where available.
Successful empty output differs from unavailable tools, access denial and
partial output. Useful partial sysctl/filesystem results remain available.
Cron covers only the effective user's crontab: root and regular users are
distinct resources. A confirmed missing crontab is empty; access denial is unknown.

Absence proves an addition/removal only when the relevant observation is complete
and the visibility scopes match. Scope changes and unreadable resources produce
`unknown` findings with reasons. Values observed in both filesystem/sysctl scans
can still prove modifications during partial collection or a privilege change.
Filesystem attributes are compared only where both scans observed them. Docker
and firewall observations with differing scopes cannot establish modifications.
A changed scope remains incomplete even when the shared values match.

Legacy snapshots remain readable and approved pointers stay valid. Previously
observed values are still compared where meaningful. Missing legacy scope cannot
prove presence/absence changes in permission-sensitive domains. Legacy
`current_user` cron entries are unknown unless older metadata proves their owner
(e.g. root). Existing global scope, partial markers and backfill provenance are
read conservatively. Re-observe and explicitly approve a reviewed snapshot to
establish a consistent collection scope; migration does not relabel historical data.

### Reports and policy

```bash
ansible-state system-drift all -i inventory.ini --report-format text
ansible-state system-drift all -i inventory.ini --policy drift-policy.json
```

Example policy (explicit opt-in globs):

```json
{"ignore": [{"domain": "services", "resource": "packagekit.service"}]}
```

Host status is `DRIFT` if confirmed configuration drift exists, `INCOMPLETE` if
required observations are unresolved without confirmed configuration drift, and
`OK` otherwise. Findings use `unknown` for unavailable or incomparable data;
unknown is never a confirmed addition, removal or modification. Hosts can have
both `has_drift` and `incomplete`; text summaries include that combination.

Runtime findings remain visible through `has_runtime_changes` but do not alone
cause configuration drift or a failing audit exit. Listener changes, service
active-state changes with unchanged unit-file settings, and Docker state changes
with unchanged image references are runtime findings. Severity labels are
heuristic, not security verdicts. Policies exclude matching confirmed findings
from the report and drift decision. **Unknown findings cannot be excluded**, so
policy filtering cannot turn failed collection into a clean report.

### Conservative baseline migration

Migration fills only wholly missing domains, preserving all known historical
values, partial historical domains and their scopes. It requires explicit
complete/scope metadata from current collection. It never fills from partial,
failed or unverifiable results. Each backfilled domain carries its own collection
metadata and provenance; comparison uses that domain's scope, including older
backfill provenance, rather than the historical host-wide scope.

```bash
# Review missing domains, existing changes and unresolved observations:
ansible-state baseline migrate all -i inventory.ini --collector-become
# Write immutable candidates and an exact-ID approval manifest:
ansible-state baseline migrate all -i inventory.ini --collector-become \
  --prepare --write-manifest migration.json
ansible-state baseline status all -i inventory.ini
# After reviewing warnings, explicitly acknowledge them if present:
ansible-state baseline approve --manifest migration.json --confirm --accept-migration-warnings
# Equivalent single-host warning acknowledgement:
ansible-state baseline approve HOST CANDIDATE_ID --accept-migration-warnings
```

Output exposes `existing_changes`, `unresolved`, `still_unavailable` and
`requires_acknowledgement`. Candidate snapshots retain this review under
`_migration`; `baseline status` exposes it too. Warning-bearing candidates require
`--accept-migration-warnings` even when approving by ID or a separately generated
manifest. Existing drift stays in the historical values and remains detectable
after migration approval. Candidates become stale if another baseline is approved
beforehand; prepare a fresh candidate. Preparing never changes approval pointers.
Manifest entries are all validated before any approval, but updates across hosts
are not transactional. Retain manifests for retries; avoid concurrent approvals.

### Exit codes and limits

For snapshot/migration/system-drift collection:

- `0`: complete execution; audit has no confirmed configuration drift or unknowns.
  Runtime-only audit changes still return 0. A migration review may list safe
  backfill opportunities without returning a failure.
- `3`: partial collection, confirmed configuration drift, unresolved observations,
  or a migration candidate requiring review acknowledgement.
- `2`: total collection failure, invalid arguments/input, or local workflow failure.
- `127`: `ansible-playbook` executable missing.

`baseline status` returns 3 for hosts awaiting approval and 0 when all are approved.
Approval returns 0 on success, 2 on invalid input or unacknowledged migration warnings.
The older `apply` and registered-file `drift` commands retain Ansible exit statuses.

This remains a best-effort inventory, not a complete desired-state model. Missing
tools are unresolved observations, including missing Docker/firewall tools. No
optional-domain policy currently suppresses those failures. No home-directory scan,
all-user crontab enumeration, IPv6 iptables fallback, Podman/Kubernetes inventory,
Docker image digest/config inspection or general runtime counter detection is
provided. Docker contexts/endpoints and UID are tracked, but daemon replacement
behind the same endpoint is not detected. Scans are not atomic: concurrent host
changes may yield partial observations. Prefer stable collection privileges and
review every baseline. Multi-host snapshots and approvals are per host, not a
group-wide desired state.
