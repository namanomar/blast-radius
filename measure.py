"""Measure what a list of ``Op`` objects would actually touch on disk.

Read-only.  The only subprocesses are ``git rev-parse`` and ``git status`` (argv lists,
GIT_OPTIONAL_LOCKS=0 so nothing is written to the repository, hard timeouts).
"""

from __future__ import annotations

import fnmatch
import glob
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from . import analyzer as A

SECRET_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12", "id_rsa*", "id_ed25519*", "id_ecdsa*",
    "*.kdbx", ".netrc", ".npmrc", ".pypirc", "credentials", "credentials.*", "secrets.*",
    "*.tfstate", "service-account*.json", "*.keystore",
)
_SENSITIVE_HOME_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".azure", ".config/gcloud")
_POSIX_SYSTEM_ROOTS = ("/", "/bin", "/sbin", "/usr", "/etc", "/lib", "/lib64", "/boot", "/dev",
                       "/proc", "/sys", "/var", "/system", "/library", "/applications", "/private")
_POSIX_SYSTEM_TREES = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/etc", "/lib", "/lib64",
                       "/boot", "/system", "/library")


@dataclass
class Limits:
    max_scan_files: int = 20000
    scan_seconds: float = 4.0
    git_seconds: float = 8.0


@dataclass
class GitState:
    root: Path
    dirty: Set[str] = field(default_factory=set)
    untracked: Set[str] = field(default_factory=set)
    ignored_files: Set[str] = field(default_factory=set)
    ignored_prefixes: List[str] = field(default_factory=list)
    ok: bool = True

    def classify(self, p: Path) -> str:
        try:
            rel = p.resolve().relative_to(self.root.resolve()).as_posix()
        except (ValueError, OSError):
            return "untracked"
        if not self.ok:
            return "untracked"
        if rel in self.dirty:
            return "dirty"
        if rel in self.untracked:
            return "untracked"
        if rel in self.ignored_files or any(rel == pre.rstrip("/") or rel.startswith(pre) for pre in self.ignored_prefixes):
            return "ignored"
        return "clean"


@dataclass
class Impact:
    files: int = 0
    dirs: int = 0
    bytes: int = 0
    dirty: List[str] = field(default_factory=list)
    untracked: List[str] = field(default_factory=list)
    ignored: int = 0
    clean: int = 0
    secrets: List[str] = field(default_factory=list)
    outside: List[str] = field(default_factory=list)
    critical: List[str] = field(default_factory=list)       # reasons that always block
    sensitive: List[str] = field(default_factory=list)      # reasons that raise the score
    missing: List[str] = field(default_factory=list)
    unresolved: bool = False
    unresolved_recursive: bool = False
    upper_bound: bool = False
    truncated: bool = False
    whole_workspace: bool = False
    sample: List[str] = field(default_factory=list)
    at_risk: List[str] = field(default_factory=list)        # absolute paths worth backing up
    shrink: Optional[Tuple[int, int]] = None                # (old_lines, new_lines) for write_file
    notes: List[str] = field(default_factory=list)
    ops: List[A.Op] = field(default_factory=list)
    git_repos: List[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return (self.files == 0 and self.dirs == 0 and not self.unresolved and not self.critical
                and not self.sensitive and self.shrink is None)


# --------------------------------------------------------------------------- paths


def _home() -> Path:
    return Path(os.path.expanduser("~")).resolve()


def _hermes_home() -> Optional[Path]:
    try:
        from hermes_constants import get_hermes_home
        return Path(get_hermes_home()).resolve()
    except Exception:
        return None


def _norm(p: Path) -> Path:
    try:
        return p.resolve()
    except (OSError, RuntimeError):
        return Path(os.path.abspath(str(p)))


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _expand(raw: str, op_cwd: Optional[str], base: Path) -> List[Path]:
    """Expand ~ and globs; relative paths resolve against the op's cwd, else the base cwd."""
    raw = os.path.expanduser(raw)
    cwd = base
    if op_cwd:
        oc = Path(os.path.expanduser(op_cwd))
        cwd = oc if oc.is_absolute() else base / oc
    full = raw if os.path.isabs(raw) else os.path.join(str(cwd), raw)
    if any(ch in raw for ch in "*?["):
        hits = glob.glob(full, recursive=True)
        return [Path(h) for h in sorted(hits)[:5000]]
    return [Path(full)]


def _protected(p: Path, cwd: Path, home: Path, hermes_home: Optional[Path]) -> Tuple[List[str], List[str], bool]:
    """Returns (critical reasons, sensitive reasons, is_whole_workspace)."""
    crit: List[str] = []
    sens: List[str] = []
    rp = _norm(p)
    low = str(rp).replace("\\", "/").lower().rstrip("/") or "/"
    whole = False

    if rp == Path(rp.anchor) or low in ("/", ""):
        crit.append("the filesystem root")
    if rp == home:
        crit.append("your entire home directory")
    elif _is_within(home, rp):
        crit.append("a parent of your home directory")
    if low in _POSIX_SYSTEM_ROOTS and low != "/":
        crit.append(f"the system directory {rp}")
    if os.name == "nt":
        wl = low
        for sysdir in ("c:/windows", "c:/program files", "c:/program files (x86)", "c:/programdata", "c:/users"):
            if wl == sysdir:
                crit.append(f"the system directory {rp}")
            elif wl.startswith(sysdir + "/") and sysdir in ("c:/windows", "c:/program files", "c:/program files (x86)"):
                sens.append(f"inside {sysdir.upper()}")
    for tree in _POSIX_SYSTEM_TREES:
        if low.startswith(tree + "/") and low != tree:
            sens.append(f"inside the system tree {tree}")
            break
    if rp.name == ".git" and rp.is_dir():
        crit.append("the .git directory (all repository history)")
    elif rp.name == "objects" and rp.parent.name == ".git":
        crit.append("the git object database")
    if hermes_home and (rp == hermes_home or _is_within(hermes_home, rp)):
        crit.append("Hermes' own data directory")
    for d in _SENSITIVE_HOME_DIRS:
        sd = home / d
        if rp == sd or _is_within(rp, sd):
            sens.append(f"credentials under ~/{d}")
            break
    if rp == cwd or _is_within(cwd, rp):
        whole = True
    return crit, sens, whole


# --------------------------------------------------------------------------- git


def _run_git(args: List[str], cwd: Path, timeout: float) -> Optional[str]:
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        r = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, timeout=timeout,
                           env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.decode("utf-8", "replace")


class _GitCache:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.roots: Dict[str, Optional[Path]] = {}
        self.states: Dict[str, GitState] = {}

    def root_for(self, p: Path) -> Optional[Path]:
        d = p if p.is_dir() else p.parent
        while not d.exists() and d != d.parent:
            d = d.parent
        key = str(d)
        if key in self.roots:
            return self.roots[key]
        out = _run_git(["rev-parse", "--show-toplevel"], d, 3.0)
        root = Path(out.strip()) if out and out.strip() else None
        self.roots[key] = root
        return root

    def state_for_root(self, root: Path) -> GitState:
        key = str(root)
        if key in self.states:
            return self.states[key]
        out = _run_git(["status", "--porcelain=v1", "-z", "-uall", "--ignored=traditional"], root, self.limits.git_seconds)
        st = GitState(root=root)
        if out is None:
            st.ok = False
        else:
            parts = out.split("\0")
            i = 0
            while i < len(parts):
                ent = parts[i]
                i += 1
                if len(ent) < 4:
                    continue
                xy, path = ent[:2], ent[3:]
                if xy[0] in "RC":
                    i += 1  # skip the original name of a rename/copy
                if xy == "??":
                    st.untracked.add(path)
                elif xy == "!!":
                    if path.endswith("/"):
                        st.ignored_prefixes.append(path)
                    else:
                        st.ignored_files.add(path)
                else:
                    st.dirty.add(path)
        self.states[key] = st
        return st

    def classify(self, p: Path) -> Tuple[str, Optional[GitState]]:
        root = self.root_for(p)
        if root is None:
            return "untracked", None
        st = self.state_for_root(root)
        return st.classify(p), st


# --------------------------------------------------------------------------- measuring


def _is_secret(name: str) -> bool:
    n = name.lower()
    return any(fnmatch.fnmatch(n, pat) for pat in SECRET_PATTERNS)


class _Scan:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.t0 = time.monotonic()
        self.n = 0
        self.stop = False

    def tick(self) -> bool:
        self.n += 1
        if self.n >= self.limits.max_scan_files or (self.n % 256 == 0 and time.monotonic() - self.t0 > self.limits.scan_seconds):
            self.stop = True
        return self.stop


def _add_file(imp: Impact, p: Path, git: _GitCache, seen: Set[str], size_hint: Optional[int] = None) -> None:
    key = str(p)
    if key in seen:
        return
    seen.add(key)
    try:
        size = size_hint if size_hint is not None else p.lstat().st_size
    except OSError:
        return
    imp.files += 1
    imp.bytes += size
    if len(imp.sample) < 12:
        imp.sample.append(key)
    kind, st = git.classify(p)
    if ".git" in p.parts:
        kind = "ignored"      # repository metadata: reported via the .git critical reason instead
    if st is not None and str(st.root) not in imp.git_repos:
        imp.git_repos.append(str(st.root))
    secret = _is_secret(p.name)
    if secret:
        imp.secrets.append(key)
    if kind == "dirty":
        imp.dirty.append(key)
        imp.at_risk.append(key)
    elif kind == "untracked":
        imp.untracked.append(key)
        imp.at_risk.append(key)
    elif kind == "ignored":
        imp.ignored += 1
        if secret:
            imp.at_risk.append(key)
    else:
        imp.clean += 1
        if secret:
            imp.at_risk.append(key)


def _walk_dir(imp: Impact, root: Path, git: _GitCache, scan: _Scan, seen: Set[str]) -> None:
    imp.dirs += 1
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # dirs that are themselves symlinks are removed as a link, not followed
        for d in list(dirnames):
            dp = Path(dirpath) / d
            if dp.is_symlink():
                dirnames.remove(d)
                _add_file(imp, dp, git, seen, size_hint=0)
            else:
                imp.dirs += 1
        for f in filenames:
            if scan.tick():
                imp.truncated = True
                return
            _add_file(imp, Path(dirpath) / f, git, seen)


def _count_lines(p: Path, limit_bytes: int = 5_000_000) -> Optional[int]:
    try:
        if p.stat().st_size > limit_bytes:
            return None
        with open(p, "rb") as fh:
            data = fh.read()
        if b"\0" in data[:4096]:
            return None
        return data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    except OSError:
        return None


def measure(ops: List[A.Op], cwd: Path, limits: Optional[Limits] = None) -> Impact:
    limits = limits or Limits()
    imp = Impact(ops=list(ops))
    git = _GitCache(limits)
    scan = _Scan(limits)
    seen: Set[str] = set()
    home = _home()
    hh = _hermes_home()
    cwd = _norm(cwd)
    tmp_roots = {_norm(Path(tempfile.gettempdir())), Path("/tmp"), Path("/var/tmp")}

    def check_target(p: Path) -> None:
        crit, sens, whole = _protected(p, cwd, home, hh)
        for c in crit:
            if c not in imp.critical:
                imp.critical.append(c)
        for s in sens:
            if s not in imp.sensitive:
                imp.sensitive.append(s)
        if whole:
            imp.whole_workspace = True
        rp = _norm(p)
        if not _is_within(rp, cwd) and not any(_is_within(rp, t) for t in tmp_roots):
            if str(rp) not in imp.outside:
                imp.outside.append(str(rp))

    for op in ops:
        if op.unresolved:
            imp.unresolved = True
            if op.recursive or op.kind == A.OPAQUE:
                imp.unresolved_recursive = True
        if op.upper_bound:
            imp.upper_bound = True
        if op.kind == A.OPAQUE:
            imp.notes.append(op.detail)
            continue
        if op.kind == A.DISK:
            imp.critical.append(f"a raw disk operation ({op.detail})")
            continue

        if op.kind in (A.GIT_DISCARD, A.GIT_CLEAN):
            gd = Path(os.path.expanduser(op.git_dir)) if op.git_dir else cwd
            if not gd.is_absolute():
                gd = cwd / gd
            root = git.root_for(gd) if gd.exists() else None
            if root is None:
                continue
            st = git.state_for_root(root)
            if str(root) not in imp.git_repos:
                imp.git_repos.append(str(root))
            specs = [p for p in op.paths if p not in (".",)]
            if op.kind == A.GIT_DISCARD:
                cand = sorted(st.dirty)
            else:
                cand = sorted(st.untracked | (st.ignored_files if not op.exclude_untracked_ignored else set()))
                if not op.exclude_untracked_ignored:
                    for pre in st.ignored_prefixes:
                        for dp, _dn, fns in os.walk(root / pre):
                            for fn in fns:
                                if scan.tick():
                                    imp.truncated = True
                                    break
                                cand.append((Path(dp) / fn).relative_to(root).as_posix())
            for rel in cand:
                if specs and not any(rel == s.strip("/") or rel.startswith(s.strip("/") + "/") or fnmatch.fnmatch(rel, s) for s in specs):
                    continue
                _add_file(imp, root / rel, git, seen)
            continue

        # path-based ops
        for raw in op.paths:
            for p in _expand(raw, op.cwd, cwd):
                check_target(p)
                if not os.path.lexists(p):
                    imp.missing.append(str(p))
                    continue
                if op.kind == A.DELETE:
                    if p.is_symlink() or p.is_file():
                        _add_file(imp, p, git, seen)
                    elif p.is_dir():
                        if op.recursive:
                            _walk_dir(imp, p, git, scan, seen)
                        elif op.detail.startswith(("rmdir", "rd")):
                            imp.dirs += 1
                elif op.kind in (A.OVERWRITE,):
                    _overwrite_targets(imp, op, p, cwd, git, seen, scan)
                elif op.kind in (A.INPLACE, A.TRUNCATE):
                    if p.is_file():
                        _add_file(imp, p, git, seen)
            if scan.stop:
                break
        if scan.stop:
            imp.truncated = True
            break

    imp.at_risk = list(dict.fromkeys(imp.at_risk))
    return imp


def _overwrite_targets(imp: Impact, op: A.Op, dest: Path, cwd: Path, git: _GitCache, seen: Set[str], scan: _Scan) -> None:
    sources = list(op.git_flags)   # for mv/cp the analyzer stores the source words here
    if dest.is_file() or dest.is_symlink():
        try:
            if dest.stat().st_size > 0 or not sources:
                _add_file(imp, dest, git, seen)
        except OSError:
            pass
        return
    if dest.is_dir() and sources:
        for s in sources:
            for sp in _expand(s, op.cwd, cwd):
                if sp.is_file():
                    t = dest / sp.name
                    if t.is_file():
                        _add_file(imp, t, git, seen)
                elif sp.is_dir():
                    for dp, _dn, fns in os.walk(sp):
                        for fn in fns:
                            if scan.tick():
                                imp.truncated = True
                                return
                            rel = (Path(dp) / fn).relative_to(sp)
                            t = dest / sp.name / rel
                            if t.is_file():
                                _add_file(imp, t, git, seen)


def measure_write(path: str, new_content: Optional[str], cwd: Path, limits: Optional[Limits] = None) -> Impact:
    """Impact of overwriting one file with write_file (including how much of it shrinks)."""
    p = Path(os.path.expanduser(path))
    if not p.is_absolute():
        p = cwd / p
    imp = measure([A.Op(A.OVERWRITE, [str(p)], detail="write_file")], cwd, limits)
    if p.is_file() and new_content is not None:
        old = _count_lines(p)
        if old is not None:
            new = new_content.count("\n") + (0 if new_content.endswith("\n") or not new_content else 1)
            imp.shrink = (old, new)
    return imp
