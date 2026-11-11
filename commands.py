"""`/blast` slash command and `hermes blast` CLI share this dispatcher."""

from __future__ import annotations

import time
from typing import Callable

from . import capsule, ledger
from .engine import agent_cwd, assess_call
from .policy import Config
from .render import human_bytes, render_approval, render_ledger_line

HELP = """blast-radius: measures what a command will destroy before it runs.

/blast                  status, savings and recent decisions
/blast explain <cmd>    preview the blast radius of a shell command (runs nothing)
/blast list             recovery capsules
/blast undo             restore the newest capsule that was actually used
/blast restore <id> [--force]
                        restore a capsule (never overwrites newer edits unless --force)
/blast stats            counters
"""


def _fmt_ts(t: float) -> str:
    return time.strftime("%m-%d %H:%M", time.localtime(t))


def run(raw: str, cfg_getter: Callable[[], Config]) -> str:
    parts = (raw or "").strip().split()
    sub = parts[0].lower() if parts else "status"
    rest = (raw or "").strip()[len(parts[0]):].strip() if parts else ""

    if sub in ("help", "-h", "--help"):
        return HELP

    if sub == "explain":
        if not rest:
            return "usage: /blast explain <shell command>"
        a = assess_call("terminal", {"command": rest, "workdir": str(agent_cwd())}, cfg_getter())
        if a is None:
            return "No destructive operation found in that command: blast radius is zero."
        return render_approval(a)

    if sub == "list":
        ms = capsule.list_capsules()
        if not ms:
            return "No capsules yet. One is created automatically when a command would destroy files git cannot restore."
        lines = ["id                    when         files  size      status    reason"]
        for m in ms[:20]:
            lines.append(f"{m['id']:<21} {_fmt_ts(m['created'])}  {len(m['entries']):>5}  "
                         f"{human_bytes(m['bytes']):<9} {m.get('status', '?'):<9} {m['reason'][:50]}")
        return "\n".join(lines)

    if sub == "stats":
        s = ledger.stats()
        return ("blast-radius counters\n"
                f"  commands measured     {s['checked']}\n"
                f"  let through silently  {s['allowed']}\n"
                f"  sent for approval     {s['approvals']}\n"
                f"  blocked               {s['blocks']}\n"
                f"  capsules taken        {s['capsules']}  ({s['files_protected']} files, {human_bytes(s['bytes_protected'])})\n"
                f"  restores              {s['restores']}\n"
                f"  commands that did nothing (capsule dropped) {s['nothing_happened']}")

    if sub in ("undo", "restore"):
        force = "--force" in parts
        ids = [p for p in parts[1:] if p.startswith("bx-")]
        if sub == "undo" and not ids:
            used = capsule.latest_used()
            if not used:
                return "Nothing to undo: no capsule from an executed command."
            ids = [used["id"]]
        if not ids:
            return "usage: /blast restore <capsule-id> [--force]   (see /blast list)"
        try:
            restored, same, refused = capsule.restore(ids[0], force=force)
        except KeyError as e:
            return str(e)
        ledger.record({"type": "restore", "capsule": ids[0], "restored": len(restored), "refused": len(refused)})
        lines = [f"Capsule {ids[0]}: restored {len(restored)} file(s)."]
        if same:
            lines.append(f"{len(same)} file(s) already identical, left alone.")
        if refused:
            lines.append(f"REFUSED {len(refused)} file(s) that changed after the capsule (re-run with --force to overwrite; "
                         f"your current copy is kept):")
            lines += ["  " + p for p in refused[:8]]
        return "\n".join(lines)

    # status (default)
    s = ledger.stats()
    ev = [e for e in ledger.read(200) if e.get("type") == "decision"][-6:]
    out = [f"blast-radius active. {s['checked']} measured, {s['approvals']} escalated, {s['blocks']} blocked, "
           f"{s['capsules']} capsule(s) taken, {s['restores']} restore(s)."]
    if ev:
        out.append("recent:")
        out += ["  " + render_ledger_line(e) for e in ev]
    out.append("try: /blast explain rm -rf build   |   /blast undo   |   /blast help")
    return "\n".join(out)
