"""Human-readable renderings of an assessment (approval prompt, block message, previews)."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from .engine import Assessment


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{int(f)} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{n} B"


def _short(paths: List[str], n: int = 3) -> str:
    base = os.getcwd()
    names = []
    for p in paths[:n]:
        try:
            rel = os.path.relpath(p, base)
            names.append(p if rel.startswith("..") else rel)
        except ValueError:
            names.append(p)
    more = len(paths) - n
    return ", ".join(names) + (f", +{more} more" if more > 0 else "")


def _bar(score: int, width: int = 20) -> str:
    filled = round(width * score / 100)
    return "#" * filled + "-" * (width - filled)


def _cmd(a: Assessment, limit: int = 160) -> str:
    c = " ".join(a.label.split())
    return c if len(c) <= limit else c[: limit - 1] + "…"


def _facts(a: Assessment) -> List[str]:
    i = a.impact
    lines: List[str] = []
    if i.files or i.dirs:
        lines.append(f"{i.files} file(s), {i.dirs} dir(s), {human_bytes(i.bytes)}"
                     + ("  (scan limit reached: real total is larger)" if i.truncated else "")
                     + ("  (upper bound)" if i.upper_bound else ""))
    for c in i.critical:
        lines.append(f"!! TARGETS {c}")
    if i.dirty:
        lines.append(f"!  {len(i.dirty)} file(s) with UNCOMMITTED changes: {_short(i.dirty)}")
    if i.untracked:
        lines.append(f"!  {len(i.untracked)} file(s) not in git, no other copy: {_short(i.untracked)}")
    if i.secrets:
        lines.append(f"!  {len(i.secrets)} credential file(s): {_short(i.secrets)}")
    if i.sensitive:
        lines.append("!  " + "; ".join(i.sensitive))
    if i.outside:
        lines.append(f"!  outside the working directory: {_short(i.outside, 2)}")
    if i.unresolved:
        lines.append("!  targets cannot be determined from the command text")
    if i.whole_workspace and i.files:
        lines.append("!  this removes the entire workspace")
    if i.shrink:
        lines.append(f"!  file shrinks {i.shrink[0]} -> {i.shrink[1]} lines")
    if i.ignored or i.clean:
        lines.append(f"   recoverable: {i.clean} tracked-clean (git checkout), {i.ignored} git-ignored (regenerable)")
    for n in i.notes:
        lines.append(f"   note: {n}")
    return lines


def _why(a: Assessment) -> str:
    return ", ".join(f"{w} (+{p})" for p, w in sorted(a.verdict.reasons, reverse=True)[:5])


def render_approval(a: Assessment) -> str:
    v = a.verdict
    out = [f"BLAST RADIUS  [{_bar(v.score)}] {v.tier} {v.score}/100", f"  {_cmd(a)}"]
    out += ["  " + ln for ln in _facts(a)]
    if a.capsule:
        m = a.capsule
        n = len(m["entries"])
        out.append(f"  Safety net: capsule {m['id']} holds {n} irreplaceable file(s) ({human_bytes(m['bytes'])})"
                   + ("  -- PARTIAL, over the size cap" if m.get("partial") else ""))
        out.append(f"  Undo after the fact: /blast restore {m['id']}   (or: /blast undo)")
    elif a.impact.at_risk is not None and not a.impact.at_risk:
        out.append("  Safety net: nothing here is unrecoverable (everything is clean in git or regenerable)")
    out.append(f"  Why {v.score}: {_why(a)}")
    return "\n".join(out)


def render_block(a: Assessment, mode: str) -> str:
    v = a.verdict
    if v.unmeasurable:
        return "\n".join([
            f"Blocked by blast-radius (strict mode): its effect cannot be measured, {v.unmeasurable}.",
            f"Command: {_cmd(a)}",
            "Rewrite it with explicit literal paths and balanced quotes so the damage can be measured, "
            "or ask the user to run it themselves. "
            "(Use the blast_radius tool to preview the rewritten command first.)"])
    head = "Blocked by blast-radius: " + (
        "this command targets " + "; ".join(v.critical) if v.critical
        else f"risk score {v.score}/100 is above the block threshold")
    out = [head + ".", f"Command: {_cmd(a)}"]
    out += _facts(a)
    out.append("Do not retry this form. Narrow it to specific paths inside the workspace, or ask the user "
               "to run it themselves if they really intend it. "
               "(Use the blast_radius tool to preview a narrower command first.)")
    return "\n".join(out)


def preview_dict(a: Assessment) -> Dict[str, Any]:
    i = a.impact
    return {
        "command": _cmd(a, 300), "action": a.verdict.action, "score": a.verdict.score, "tier": a.verdict.tier,
        "files": i.files, "dirs": i.dirs, "bytes": i.bytes,
        "uncommitted_changes": len(i.dirty), "not_in_git": len(i.untracked), "secrets": len(i.secrets),
        "recoverable_via_git": i.clean, "regenerable_ignored": i.ignored,
        "critical": a.verdict.critical, "unresolved": i.unresolved, "outside_workspace": i.outside[:5],
        "why": [{"points": p, "reason": w} for p, w in a.verdict.reasons],
        "summary": "\n".join(_facts(a)),
        "advice": ("Safe to run." if a.verdict.action == "allow"
                   else "Would need human approval." if a.verdict.action == "approve"
                   else "Would be blocked. Narrow the scope."),
    }


def render_ledger_line(e: Dict[str, Any]) -> str:
    t = time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0)))
    return f"{t}  {e.get('action', '?'):<7} {e.get('score', 0):>3}  {e.get('cmd', '')[:90]}"
