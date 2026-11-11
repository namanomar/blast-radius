"""Assessment pipeline shared by the hook, the tools and the slash/CLI commands."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from . import analyzer as A
from . import capsule
from .measure import Impact, Limits, measure, measure_write
from .policy import ALLOW, BLOCK, Config, Verdict, score

TERMINAL_TOOLS = {"terminal"}
WATCHED = {"terminal", "execute_code", "write_file", "patch"}


@dataclass
class Assessment:
    tool: str
    label: str            # command line or path, for display
    impact: Impact
    verdict: Verdict
    capsule: Optional[Dict[str, Any]] = None


def agent_cwd(args: Optional[Dict[str, Any]] = None) -> Path:
    wd = (args or {}).get("workdir")
    if isinstance(wd, str) and wd.strip():
        p = Path(os.path.expanduser(wd))
        if p.is_dir():
            return p
    try:
        from agent.runtime_cwd import resolve_agent_cwd
        return Path(resolve_agent_cwd())
    except Exception:
        return Path(os.getcwd())


def _limits(cfg: Config) -> Limits:
    return Limits(max_scan_files=cfg.max_scan_files)


def assess_call(tool: str, args: Dict[str, Any], cfg: Config) -> Optional[Assessment]:
    """Measure a pending tool call. Returns None when the call has nothing destructive in it."""
    if not isinstance(args, dict):
        return None
    cwd = agent_cwd(args)
    if tool == "terminal":
        cmd = args.get("command")
        if not isinstance(cmd, str):
            return None
        try:
            ops = A.analyze_command(cmd, cwd=None, strict=cfg.strict)
        except A.AnalysisError as e:
            return unmeasurable(tool, cmd, str(e))
        if not ops:
            return None
        return _finish(tool, cmd, measure(ops, cwd, _limits(cfg)), cfg)
    if tool == "execute_code":
        code = args.get("code")
        if isinstance(code, str) and A._opaque_in(code):
            ops = [A.Op(A.OPAQUE, [], unresolved=True, detail="code that deletes files")]
            return _finish(tool, code[:200].replace("\n", " "), measure(ops, cwd, _limits(cfg)), cfg)
        return None
    if tool == "write_file":
        path = args.get("path")
        if not isinstance(path, str) or not path:
            return None
        imp = measure_write(path, args.get("content") if isinstance(args.get("content"), str) else None,
                            cwd, _limits(cfg))
        if imp.empty:
            return None
        return _finish(tool, path, imp, cfg)
    if tool == "patch":
        ops = []
        body = args.get("patch")
        if isinstance(body, str):
            ops.extend(A.analyze_patch(body))
        path = args.get("path")
        if isinstance(path, str) and path:
            ops.append(A.Op(A.INPLACE, [path], detail="patch"))
        if not ops:
            return None
        imp = measure(ops, cwd, _limits(cfg))
        if imp.empty:
            return None
        label = path if isinstance(path, str) and path else "patch"
        return _finish(tool, label, imp, cfg)
    return None


def unmeasurable(tool: str, label: str, why: str) -> Assessment:
    """Strict mode: a call blast-radius cannot measure is blocked, not waved through."""
    v = Verdict(BLOCK, 100, "UNMEASURABLE", [(100, why)], unmeasurable=why)
    return Assessment(tool=tool, label=label, impact=Impact(), verdict=v)


def _finish(tool: str, label: str, imp: Impact, cfg: Config) -> Assessment:
    verdict = score(imp, cfg)
    return Assessment(tool=tool, label=label, impact=imp, verdict=verdict)


def make_capsule(a: Assessment, cfg: Config) -> Optional[Dict[str, Any]]:
    """Back up what git cannot restore. Re-scores if the capsule had to be partial."""
    if not cfg.capsules or not a.impact.at_risk or a.verdict.action == "block":
        return None
    try:
        m = capsule.create(a.impact.at_risk, f"{a.tool}: {a.label}", cfg.capsule_max_mb,
                           meta={"tool": a.tool})
    except Exception:
        return None
    if m:
        a.capsule = m
        if m.get("partial"):
            a.verdict = score(a.impact, cfg, partial_capsule=True)
    return m
