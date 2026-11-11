"""Append-only local ledger of decisions (JSON lines) plus aggregate stats."""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List

from . import capsule

_SECRET_RE = re.compile(r"(?i)((?:token|key|secret|passw(?:or)?d|auth|bearer)\s*[=:]\s*)\S+")


def _path():
    return capsule.data_dir() / "ledger.jsonl"


def redact(text: str) -> str:
    return _SECRET_RE.sub(r"\1***", text or "")


def record(event: Dict[str, Any]) -> None:
    try:
        event = dict(event)
        event["ts"] = round(time.time(), 2)
        if "cmd" in event:
            event["cmd"] = redact(str(event["cmd"]))[:300]
        with open(_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read(limit: int = 0) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(_path(), encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out[-limit:] if limit else out


def stats() -> Dict[str, Any]:
    ev = read()
    s = {"checked": 0, "allowed": 0, "approvals": 0, "blocks": 0, "capsules": 0,
         "restores": 0, "bytes_protected": 0, "files_protected": 0, "nothing_happened": 0}
    for e in ev:
        t = e.get("type")
        if t == "decision":
            s["checked"] += 1
            a = e.get("action")
            if a == "allow":
                s["allowed"] += 1
            elif a == "approve":
                s["approvals"] += 1
            elif a == "block":
                s["blocks"] += 1
            if e.get("capsule"):
                s["capsules"] += 1
                s["bytes_protected"] += int(e.get("capsule_bytes", 0))
                s["files_protected"] += int(e.get("capsule_files", 0))
        elif t == "restore":
            s["restores"] += int(e.get("restored", 0) > 0)
        elif t == "noop":
            s["nothing_happened"] += 1
    return s
