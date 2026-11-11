"""Scoring: turn a measured ``Impact`` into an explainable 0-100 risk score and a decision.

Every point in the score comes with a human-readable reason, so the prompt shown to the
operator (and the message returned to the model on a block) says exactly *why*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from . import analyzer as A
from .measure import Impact

ALLOW, APPROVE, BLOCK = "allow", "approve", "block"


@dataclass
class Config:
    enabled: bool = True
    mode: str = "enforce"            # enforce | advise  (advise never blocks, only asks)
    approve_score: int = 40
    block_score: int = 90
    capsules: bool = True
    capsule_max_mb: int = 200
    capsule_keep: int = 200
    capsule_days: int = 14
    max_scan_files: int = 20000
    shrink_pct: int = 70
    shrink_min_lines: int = 40

    @classmethod
    def from_getter(cls, get) -> "Config":
        c = cls()
        for name, typ in (("enabled", bool), ("mode", str), ("approve_score", int), ("block_score", int),
                          ("capsules", bool), ("capsule_max_mb", int), ("capsule_keep", int),
                          ("capsule_days", int), ("max_scan_files", int), ("shrink_pct", int),
                          ("shrink_min_lines", int)):
            try:
                v = get(name, getattr(c, name))
            except Exception:
                continue
            try:
                if typ is bool and isinstance(v, str):
                    v = v.strip().lower() in ("1", "true", "yes", "on")
                setattr(c, name, typ(v))
            except (TypeError, ValueError):
                pass
        if c.mode not in ("enforce", "advise"):
            c.mode = "enforce"
        return c


@dataclass
class Verdict:
    action: str
    score: int
    tier: str
    reasons: List[Tuple[int, str]] = field(default_factory=list)
    critical: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "score": self.score, "tier": self.tier,
                "reasons": [{"points": p, "why": w} for p, w in self.reasons], "critical": self.critical}


def _files_points(n: int) -> int:
    if n <= 0:
        return 0
    if n < 5:
        return 2
    if n < 25:
        return 8
    if n < 100:
        return 18
    if n < 500:
        return 30
    return 45


def _bytes_points(b: int) -> int:
    mb = b / (1024 * 1024)
    if mb >= 1024:
        return 35
    if mb >= 100:
        return 20
    if mb >= 10:
        return 8
    return 0


def tier_for(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "ELEVATED"
    if score >= 15:
        return "MODERATE"
    return "LOW"


def score(imp: Impact, cfg: Config, partial_capsule: bool = False) -> Verdict:
    reasons: List[Tuple[int, str]] = []

    def add(points: int, why: str) -> None:
        if points:
            reasons.append((points, why))

    add(_files_points(imp.files), f"{imp.files} file(s) affected")
    add(_bytes_points(imp.bytes), "large amount of data")
    if imp.dirty:
        add(min(45, 28 + 4 * len(imp.dirty)), f"{len(imp.dirty)} file(s) with UNCOMMITTED git changes")
    if imp.untracked:
        add(min(35, 8 + len(imp.untracked)), f"{len(imp.untracked)} file(s) not in git (no other copy)")
    if imp.secrets:
        add(25, f"{len(imp.secrets)} credential/secret file(s)")
    if imp.unresolved:
        add(45 if imp.unresolved_recursive else 25,
            "targets cannot be determined (shell variables, xargs or opaque code)")
    if imp.files and any(op.kind in (A.GIT_DISCARD, A.GIT_CLEAN) for op in imp.ops):
        add(15, "git discards cannot be undone with git itself")
    if imp.outside:
        add(15, "outside the working directory")
    if imp.sensitive:
        add(30, "; ".join(imp.sensitive))
    if imp.whole_workspace and imp.files:
        add(25, "removes the whole workspace")
    if imp.upper_bound or imp.truncated:
        add(10, "scope is an upper bound (pattern filter or scan limit)")
    if partial_capsule:
        add(10, "too large to fully back up")
    if imp.shrink:
        old, new = imp.shrink
        if old >= cfg.shrink_min_lines and new <= old * (100 - cfg.shrink_pct) / 100.0:
            add(50, f"file shrinks from {old} to {new} lines")

    total = min(100, sum(p for p, _ in reasons))
    tier = tier_for(total)
    if imp.critical:
        return Verdict(BLOCK, 100, "CRITICAL", reasons, list(imp.critical))
    if total >= cfg.block_score and cfg.mode == "enforce":
        return Verdict(BLOCK, total, tier, reasons)
    if total >= cfg.approve_score:
        return Verdict(APPROVE, total, tier, reasons)
    return Verdict(ALLOW, total, tier, reasons)
