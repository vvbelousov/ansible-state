"""Read-only Ansible callback emitting minimal JSONL observations."""
from __future__ import annotations

import json
import os
import re

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
        args = getattr(task, "args", {}) or {}
        event = {"status": status, "action": action,
                 "host": result._host.get_name()}
        if os.environ.get("ANSIBLE_STATE_INVENTORY") == "1":
            if task.get_name() != "ansible-state inventory":
                return
            if status == "ok":
                event["inventory"] = data.get("stdout", "")
            else:
                event["error"] = " ".join(str(data.get(key, "")) for key in
                                          ("msg", "stderr", "module_stderr", "stdout"))[:2000]
        elif os.environ.get("ANSIBLE_STATE_DRIFT") == "1":
            match = re.fullmatch(r"ansible-state inspection (\d+)", task.get_name())
            if not match or action not in ("stat", "ansible.builtin.stat"):
                return
            event["inspection_index"] = int(match.group(1))
            stat = data.get("stat", {})
            event["stat"] = {k: stat[k] for k in
                             ("exists", "checksum", "mode", "owner", "group", "pw_name", "gr_name")
                             if k in stat}
        else:
            if action not in ("copy", "ansible.builtin.copy", "template",
                              "ansible.builtin.template", "file", "ansible.builtin.file"):
                return
            event["result"] = {k: data[k] for k in
                               ("dest", "path", "checksum", "mode", "owner",
                                "group", "state", "size") if k in data}
            event["args"] = {k: args[k] for k in ("dest", "path", "state")
                             if isinstance(args.get(k), str)}
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")

    def v2_runner_on_ok(self, result):
        self._emit(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._emit(result, "failed")

    def v2_runner_on_skipped(self, result):
        self._emit(result, "skipped")

    def v2_runner_on_unreachable(self, result):
        self._emit(result, "unreachable")
