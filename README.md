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

The state command prints observed resources as JSON. Use \`drift\` to inspect registered paths on their recorded hosts via Ansible's read-only \`stat\` module. It compares SHA-1 checksums (where recorded), modes and ownership. Exit codes: 0 = no detected drift, 3 = drift or unknown state, other nonzero = Ansible execution error. This is not a full filesystem or desired-state scan. Observations may be incomplete.

If `ANSIBLE_CALLBACK_PLUGINS` or `ANSIBLE_CALLBACKS_ENABLED` is already
configured, the wrapper currently runs Ansible without observation rather
than replacing the existing callback configuration.

## Safety

- Existing playbooks remain runnable directly with `ansible-playbook`.
- No resource deletion, pruning or reconciliation is implemented.\n- Drift inspection reads only paths already recorded in the registry.\n- Inspection requires inventory/connectivity to the recorded hosts.\n- File metadata and checksums can be stale after ordinary Ansible runs.
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

No agent or continuous monitoring is installed. The collector runs manually over
Ansible connections and requires Python 3 on target Linux hosts.

```bash
# From your playbook directory, using your existing ansible.cfg and inventory:
ansible-state snapshot common-02.mastcloud.ru
# Example output: [{"host": "...", "snapshot_id": "32-character-hex"}]

# Explicitly accept that snapshot as the baseline:
ansible-state baseline approve common-02.mastcloud.ru SNAPSHOT_ID

# Inspect the host again and compare against approved state:
ansible-state system-drift common-02.mastcloud.ru
```

Supply regular Ansible options *after* the host pattern, e.g.
`ansible-state snapshot webservers -i inventory --become`.

The collector inventories installed dpkg/rpm packages, systemd service
unit-file and runtime states, listening TCP/UDP endpoints, local user accounts,
and metadata for files beneath `/etc`, `/usr/local/etc`, `/usr/local/bin`,
`/opt`, and `/srv`. Regular files up to 8 MiB are SHA-256 hashed.
It does not read or store file contents. Symlinks are not followed and
mount points on different devices are skipped. Inaccessible paths are marked
unreadable. Collection is best-effort and **not a complete system snapshot**.

Snapshot IDs are immutable and are never implicitly approved. The `baseline
approve` command changes only the approved snapshot pointer. `system-drift`
does not modify hosts or update the baseline. Exit status 0 means no differences
in collected domains, 3 means differences or unknown baseline, and other
nonzero statuses mean collection errors.

**Limitations:** Python must be available on remote hosts; systemd, dpkg/rpm,
and `ss` may be unavailable; SSH privileges affect visibility. The collector
does not yet track firewall rules, kernel settings, cron, container workloads,
all home directories, or files outside its scan roots. Runtime data can produce
noise. Snapshots contain usernames, local paths, and file hashes, so protect
the local `.ansible-state/` directory. Use a dedicated baseline for each host.

## Classified system drift (experimental)

```bash
ansible-state snapshot common-02.mastcloud.ru
ansible-state baseline approve common-02.mastcloud.ru SNAPSHOT_ID
ansible-state system-drift common-02.mastcloud.ru --report-format text
ansible-state system-drift common-02.mastcloud.ru --policy drift-policy.json
```

Example `drift-policy.json` (explicit opt-in exclusions, glob patterns):

```json
{"ignore": [{"domain": "services", "resource": "packagekit.service"}]}
```

The report adds `category` (`configuration` or `runtime`) and
`severity` (`info`, `warning`, `critical`) to each change. These
are heuristic labels, **not** proof of malicious activity or network exposure.
Filtering suppresses matching findings in the report and exit status; use
sparingly. Runtime-only systemd active-state changes are informational;
listener changes are runtime findings.

Additional best-effort collectors inspect current-user crontab, systemd
timer unit files, sysctl values, nftables (fallback iptables-save), and Docker
container list. Missing tools, access restrictions or failed commands produce
`unknown` findings rather than clean results. The crontab collector currently
covers only the effective user; `/etc` file inventory provides partial coverage
of system crontabs. Docker status strings and some sysctl values can be volatile.

**Baseline migration:** existing approved snapshots lack these new domains.
Take a fresh snapshot and explicitly approve it before relying on the expanded
checks. The tool does not auto-approve any changes. For accurate collection,
use appropriate Ansible become privileges. Review snapshot storage security:
firewall rules, sysctl values, and cron content may contain sensitive metadata.
