"""Recovery capsules: copies of the files a command is about to destroy.

Only files that git cannot bring back are copied (uncommitted changes, untracked files,
credential files) - files that are clean in git are one `git checkout` away, so skipping
them keeps capsules small.  Restore never overwrites a file that changed after the capsule
was taken unless forced, and a forced restore first keeps a copy of what it replaces.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def _root() -> Path:
    try:
        from plugins.plugin_storage import plugin_data_dir
        base = plugin_data_dir("blast-radius")
    except Exception:
        from hermes_constants import get_hermes_home
        base = Path(get_hermes_home()) / "plugin-data" / "blast-radius"
        base.mkdir(parents=True, exist_ok=True)
    d = Path(base) / "capsules"
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    return _root().parent


def _sha(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def create(paths: List[str], reason: str, max_mb: int = 200, meta: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Copy ``paths`` into a new capsule. Returns its manifest (with ``partial`` set if capped)."""
    if not paths:
        return None
    cid = "bx-" + time.strftime("%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    cdir = _root() / cid
    (cdir / "files").mkdir(parents=True, exist_ok=True)
    budget = max_mb * 1024 * 1024
    used = 0
    entries: List[Dict[str, Any]] = []
    skipped = 0
    for i, sp in enumerate(paths):
        src = Path(sp)
        try:
            st = src.lstat()
        except OSError:
            continue
        if used + st.st_size > budget:
            skipped += 1
            continue
        stored = cdir / "files" / f"{i:05d}"
        try:
            if src.is_symlink():
                entries.append({"orig": str(src), "stored": None, "link": os.readlink(src), "size": 0,
                                "mtime_ns": st.st_mtime_ns, "sha": None})
                continue
            shutil.copy2(src, stored)
        except OSError:
            skipped += 1
            continue
        used += st.st_size
        entries.append({"orig": str(src), "stored": stored.name, "size": st.st_size,
                        "mtime_ns": st.st_mtime_ns, "sha": _sha(stored)})
    if not entries:
        shutil.rmtree(cdir, ignore_errors=True)
        return None
    manifest = {"id": cid, "created": time.time(), "reason": reason[:300], "entries": entries,
                "partial": skipped > 0, "skipped": skipped, "bytes": used, "status": "pending",
                "meta": meta or {}}
    (cdir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest


def load(cid: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads((_root() / cid / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save(m: Dict[str, Any]) -> None:
    (_root() / m["id"] / "manifest.json").write_text(json.dumps(m, indent=1), encoding="utf-8")


def mark(cid: str, status: str) -> None:
    m = load(cid)
    if m:
        m["status"] = status
        _save(m)


def discard(cid: str) -> None:
    if cid and cid.startswith("bx-") and "/" not in cid and "\\" not in cid:
        shutil.rmtree(_root() / cid, ignore_errors=True)


def unchanged_since(m: Dict[str, Any]) -> bool:
    """True when every captured file still exists with the same size+mtime (command did nothing)."""
    for e in m.get("entries", []):
        try:
            st = os.lstat(e["orig"])
        except OSError:
            return False
        if st.st_size != e["size"] or st.st_mtime_ns != e["mtime_ns"]:
            return False
    return True


def list_capsules() -> List[Dict[str, Any]]:
    out = []
    for d in sorted(_root().iterdir(), reverse=True):
        m = load(d.name) if d.is_dir() else None
        if m:
            out.append(m)
    return out


def restore(cid: str, force: bool = False) -> Tuple[List[str], List[str], List[str]]:
    """Returns (restored, skipped_unchanged, refused). Never overwrites newer edits unless forced."""
    m = load(cid)
    if not m:
        raise KeyError(f"no capsule named {cid!r}")
    cdir = _root() / cid
    restored: List[str] = []
    same: List[str] = []
    refused: List[str] = []
    for e in m["entries"]:
        dest = Path(e["orig"])
        if e.get("link") is not None:
            if not os.path.lexists(dest):
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(e["link"], dest)
                    restored.append(str(dest))
                except OSError:
                    refused.append(str(dest))
            continue
        stored = cdir / "files" / e["stored"]
        if not stored.exists():
            refused.append(str(dest))
            continue
        if os.path.lexists(dest):
            if _sha(dest) == e["sha"]:
                same.append(str(dest))
                continue
            if not force:
                refused.append(str(dest))
                continue
            keep = cdir / "replaced" / (e["stored"] + ".bak")
            keep.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(dest, keep)
            except OSError:
                refused.append(str(dest))
                continue
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(stored, dest)
            restored.append(str(dest))
        except OSError:
            refused.append(str(dest))
    m["status"] = "restored" if restored and not refused else m.get("status", "pending")
    m["restored_at"] = time.time()
    _save(m)
    return restored, same, refused


def prune(keep: int = 200, days: int = 14) -> int:
    """Delete capsules older than ``days`` or beyond the newest ``keep``. Returns number removed."""
    removed = 0
    cutoff = time.time() - days * 86400
    for i, m in enumerate(list_capsules()):
        if i >= keep or m.get("created", 0) < cutoff:
            discard(m["id"])
            removed += 1
    return removed
