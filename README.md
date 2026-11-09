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
