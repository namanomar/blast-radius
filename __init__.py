"""blast-radius: measure what a command will destroy *before* it runs.

Hooks ``pre_tool_call`` for terminal / execute_code / write_file / patch, measures the real
filesystem and git state, and then: lets harmless calls through silently, escalates risky
ones to Hermes' approval gate with a concrete impact report, and blocks catastrophic ones.
Anything git cannot restore is copied into a recovery capsule first (`/blast undo`).
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Dict, Optional

from . import capsule, ledger
from .commands import run as run_command
from .engine import WATCHED, assess_call, make_capsule
from .policy import ALLOW, APPROVE, BLOCK, Config
from .render import preview_dict, render_approval, render_block

logger = logging.getLogger(__name__)

_ctx: Any = None
_pending: Dict[str, str] = {}       # tool-call key -> capsule id
_lock = threading.Lock()


def _cfg() -> Config:
    getter = getattr(_ctx, "get_config", None)
    if getter is None:
        return Config()
    return Config.from_getter(lambda k, d: getter(k, d))


def _key(tool_name: str, args: Dict[str, Any], kwargs: Dict[str, Any]) -> str:
    cid = kwargs.get("tool_call_id")
    if cid:
        return str(cid)
    try:
        return tool_name + ":" + json.dumps(args, sort_keys=True, default=str)[:400]
    except Exception:
        return tool_name


def _pre_tool_call(tool_name: str = "", args: Optional[Dict[str, Any]] = None, task_id: str = "", **kwargs):
    """Policy hook. Fails OPEN: a bug in this plugin must never wedge the agent."""
    if tool_name not in WATCHED:
        return None
    try:
        cfg = _cfg()
        if not cfg.enabled:
            return None
        a = assess_call(tool_name, args or {}, cfg)
        if a is None:
            return None
        make_capsule(a, cfg)
        v = a.verdict
        ledger.record({"type": "decision", "tool": tool_name, "cmd": a.label, "action": v.action,
                       "score": v.score, "tier": v.tier, "files": a.impact.files, "bytes": a.impact.bytes,
                       "capsule": a.capsule["id"] if a.capsule else None,
                       "capsule_files": len(a.capsule["entries"]) if a.capsule else 0,
                       "capsule_bytes": a.capsule["bytes"] if a.capsule else 0})
        if a.capsule:
            with _lock:
                _pending[_key(tool_name, args or {}, kwargs)] = a.capsule["id"]
        if v.action == BLOCK:
            return {"action": "block", "message": render_block(a, cfg.mode)}
        if v.action == APPROVE:
            return {"action": "approve", "message": render_approval(a), "rule_key": f"blast-radius:{tool_name}"}
        return None
    except Exception:
        logger.exception("blast-radius pre_tool_call failed; letting the call through")
        return None


def _post_tool_call(tool_name: str = "", args: Optional[Dict[str, Any]] = None, **kwargs):
    """Close the loop: drop capsules for calls that changed nothing, mark the rest executed."""
    if tool_name not in WATCHED:
        return None
    try:
        with _lock:
            cid = _pending.pop(_key(tool_name, args or {}, kwargs), None)
        if not cid:
            return None
        m = capsule.load(cid)
        if not m:
            return None
        if capsule.unchanged_since(m):
            capsule.discard(cid)
            ledger.record({"type": "noop", "capsule": cid})
        else:
            capsule.mark(cid, "executed")
    except Exception:
        logger.exception("blast-radius post_tool_call failed")
    return None


# ------------------------------------------------------------------ tools

BLAST_RADIUS_SCHEMA = {
    "name": "blast_radius",
    "description": (
        "Preview what a shell command or file write would destroy WITHOUT running it: files, bytes, "
        "uncommitted git changes, files with no other copy, credentials, and a 0-100 risk score with the "
        "decision (allow / needs human approval / blocked). Call this before rm -rf, git reset --hard, "
        "git clean, mv/cp over existing files, sed -i, or any sweeping cleanup so you can narrow the "
        "command instead of being blocked."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command to assess (not executed)."},
            "path": {"type": "string", "description": "Alternative to command: a file you plan to overwrite."},
            "content": {"type": "string", "description": "With path: the new content, to detect large shrinkage."},
        },
    },
}

BLAST_RESTORE_SCHEMA = {
    "name": "blast_restore",
    "description": (
        "Undo your own destructive command: restore files from a blast-radius recovery capsule. "
        "Pass capsule_id from an earlier approval message, or 'latest'. Never overwrites files that "
        "changed after the capsule was taken (only a human can force that with /blast restore --force)."
    ),
    "parameters": {
        "type": "object",
        "properties": {"capsule_id": {"type": "string", "description": "A capsule id like bx-1111-120000-ab12, or 'latest'."}},
        "required": ["capsule_id"],
    },
}


def _tool_blast_radius(args: Dict[str, Any], **kwargs) -> str:
    try:
        cfg = _cfg()
        if args.get("command"):
            a = assess_call("terminal", {"command": args["command"]}, cfg)
        elif args.get("path"):
            a = assess_call("write_file", {"path": args["path"], "content": args.get("content")}, cfg)
        else:
            return json.dumps({"error": "pass command or path"})
        if a is None:
            return json.dumps({"action": "allow", "score": 0, "tier": "LOW", "files": 0,
                               "advice": "No destructive operation detected. Safe to run."})
        return json.dumps(preview_dict(a))
    except Exception as e:  # tool handlers must never raise
        return json.dumps({"error": f"blast_radius failed: {e}"})


def _tool_blast_restore(args: Dict[str, Any], **kwargs) -> str:
    try:
        cid = str(args.get("capsule_id", "")).strip()
        if cid == "latest":
            used = capsule.latest_used()
            if not used:
                return json.dumps({"error": "no executed capsule to restore"})
            cid = used["id"]
        restored, same, refused = capsule.restore(cid, force=False)
        ledger.record({"type": "restore", "capsule": cid, "restored": len(restored), "refused": len(refused)})
        return json.dumps({"capsule": cid, "restored": restored, "already_identical": len(same),
                           "refused_because_changed_since": refused})
    except KeyError as e:
        return json.dumps({"error": str(e)})
    except Exception as e:
        return json.dumps({"error": f"blast_restore failed: {e}"})


# ------------------------------------------------------------------ CLI


def _cli_setup(parser) -> None:
    parser.add_argument("words", nargs="*", help="status | explain <cmd> | list | undo | restore <id> | stats")
    parser.add_argument("--force", action="store_true", help="with restore: overwrite files changed since")


def _cli_handler(args) -> None:
    words = list(getattr(args, "words", []) or [])
    if getattr(args, "force", False):
        words.append("--force")
    print(run_command(" ".join(words), _cfg))


# ------------------------------------------------------------------ entry point


def register(ctx) -> None:
    global _ctx
    _ctx = ctx
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("post_tool_call", _post_tool_call)
    ctx.register_tool(name="blast_radius", toolset="blast-radius", schema=BLAST_RADIUS_SCHEMA,
                      handler=_tool_blast_radius)
    ctx.register_tool(name="blast_restore", toolset="blast-radius", schema=BLAST_RESTORE_SCHEMA,
                      handler=_tool_blast_restore)
    ctx.register_command("blast", lambda raw="", **kw: run_command(raw, _cfg),
                         description="Blast radius: preview, undo and audit destructive commands",
                         args_hint="[explain <cmd>|undo|list|restore <id>|stats]")
    ctx.register_cli_command(name="blast", help="Blast-radius capsules and previews",
                             setup_fn=_cli_setup, handler_fn=_cli_handler)
    try:
        cfg = _cfg()
        capsule.prune(cfg.capsule_keep, cfg.capsule_days)
    except Exception:
        logger.debug("capsule prune skipped", exc_info=True)
