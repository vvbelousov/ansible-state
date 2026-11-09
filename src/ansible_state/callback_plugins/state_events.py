"""Read-only Ansible callback emitting JSONL to a wrapper-owned file."""
from __future__ import annotations

import json
import os

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "state_events"
    CALLBACK_NEEDS_ENABLED = True

    def _emit(self, result, status):
        path = os.environ.get("ANSIBLE_STATE_EVENTS")
        if not path:
            return
        task = result._task
        action = getattr(task, "action", "")
        data = result._result.copy()
        # Never persist module results wholesale: they can contain secrets.
        safe = {k: data.get(k) for k in ("dest", "path", "checksum",
                 "mode", "owner", "group", "state", "size") if k in data}
        args = getattr(task, "args", {}) or {}
        safe_args = {k: args.get(k) for k in ("dest", "path", "state")
                     if isinstance(args.get(k), str)}
        event = {"status": status, "action": action,
                 "host": result._host.get_name(), "result": safe,
                 "args": safe_args}
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")

    def v2_runner_on_ok(self, result):
        self._emit(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit(result, "failed")

    def v2_runner_on_skipped(self, result):
        self._emit(result, "skipped")
