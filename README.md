# ansible-state

Experimental, opt-in read-only resource observation for **unchanged** Ansible playbooks.

> Early prototype. This is **not** a Terraform-like plan/apply engine yet.
> No drift detection or automatic cleanup is implemented.

## Install

```bash
python -m pip install -e '.[dev]'
```

## Run

```bash
ansible-state apply -i inventory site.yml
ansible-state state
```

`apply` executes the system `ansible-playbook` command and propagates its
exit status. Successful runs record limited file/copy/template results in
`.ansible-state/state.db`. Override this location with `ANSIBLE_STATE_DB`.

The state command prints observed resources as JSON. It **does not** verify
whether they still exist or detect drift. Observations may be incomplete.

If `ANSIBLE_CALLBACK_PLUGINS` or `ANSIBLE_CALLBACKS_ENABLED` is already
configured, the wrapper currently runs Ansible without observation rather
than replacing the existing callback configuration.

## Safety

- Existing playbooks remain runnable directly with `ansible-playbook`.
- No resource deletion, pruning or reconciliation is implemented.
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
