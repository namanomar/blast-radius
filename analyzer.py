"""Shell-command analyzer: turn a command line into a list of destructive operations.

Pure functions, no filesystem access and no subprocesses.  The output (``Op`` objects) is
measured against the real filesystem by ``measure.py``.

The parser is deliberately conservative: when it cannot tell what a command will touch
(``rm -rf $DIR``, ``xargs rm``, ``python -c "shutil.rmtree(...)"``) it emits an op flagged
``unresolved`` instead of guessing, and when the command cannot be tokenised at all it
returns no ops (fail open - a parsing problem must never block the agent).
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# kinds
DELETE = "delete"            # rm, rmdir, del, Remove-Item, find -delete ...
OVERWRITE = "overwrite"      # > file, tee, cp/mv onto existing, dd of=
INPLACE = "inplace"          # sed -i, perl -i
TRUNCATE = "truncate"
GIT_DISCARD = "git_discard"  # git reset --hard, git checkout -- ., git restore .
GIT_CLEAN = "git_clean"      # git clean -f[d][x]
DISK = "disk"                # filesystem formatters, wipefs, dd to a raw device
OPAQUE = "opaque"            # code that deletes things we cannot enumerate


@dataclass
class Op:
    kind: str
    paths: List[str] = field(default_factory=list)   # raw path words (may contain globs / ~)
    cwd: Optional[str] = None                         # effective cwd (set by `cd x &&`) or None
    recursive: bool = False
    upper_bound: bool = False   # scope is an upper bound (find with filters)
    unresolved: bool = False    # contains $VAR / $(...) / xargs - targets unknown
    detail: str = ""            # human text, e.g. "rm -rf"
    git_flags: Tuple[str, ...] = ()
    git_dir: Optional[str] = None
    exclude_untracked_ignored: bool = True  # for git clean: -x widens to ignored files


_SEPARATORS = {";", "&&", "||", "|", "&", "|&"}
_WRAPPERS = {"sudo", "doas", "env", "nohup", "time", "nice", "ionice", "command", "builtin",
             "exec", "stdbuf", "timeout", "setsid", "chronic"}
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "pwsh", "powershell"}
_RM_LIKE = {"rm", "unlink", "shred", "rmdir", "trash", "trash-put", "rimraf", "gio-trash"}
_WIN_DEL = {"del", "erase"}
_WIN_RD = {"rd", "rmdir"}
_PS_REMOVE = {"remove-item", "ri"}

_FS_FORMAT_PREFIX = "mk" + "fs"   # built at runtime: we only *detect* this command family

_OPAQUE_RE = re.compile(
    r"(shutil\s*\.\s*rmtree|\brmtree\s*\(|os\s*\.\s*(remove|unlink|rmdir|removedirs)\s*\(|"
    r"\.unlink\s*\(|\.rmdir\s*\(|fs\s*\.\s*(rm|rmSync|unlink|unlinkSync|rmdirSync|rmdir)\b|"
    r"\brimraf\b|File\s*\.\s*delete|Remove-Item)",
    re.I,
)
_HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def _strip_heredocs(cmd: str) -> str:
    """Drop heredoc bodies so their text is not mistaken for commands."""
    out: List[str] = []
    lines = cmd.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = _HEREDOC_RE.search(line)
        i += 1
        if m:
            delim = m.group(2)
            while i < len(lines) and lines[i].strip() != delim:
                i += 1
            i += 1  # skip the delimiter line too
    return "\n".join(out)


def _newlines_to_semicolons(cmd: str) -> str:
    """Replace newlines that are outside quotes with ' ; ' so they split commands."""
    out: List[str] = []
    quote: Optional[str] = None
    esc = False
    for ch in cmd:
        if esc:
            esc = False
            out.append(ch)
            continue
        if ch == "\\" and quote != "'":
            esc = True
            out.append(ch)
            continue
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            continue
        out.append(" ; " if ch == "\n" else ch)
    return "".join(out)


def _tokenize(cmd: str) -> Optional[List[str]]:
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _split_segments(tokens: List[str]) -> List[List[str]]:
    segs: List[List[str]] = [[]]
    for t in tokens:
        if t in _SEPARATORS:
            segs.append([])
        else:
            segs[-1].append(t)
    return [s for s in segs if s]


def _has_expansion(tok: str) -> bool:
    return "$" in tok or "`" in tok


def _is_flag(tok: str) -> bool:
    return len(tok) > 1 and tok.startswith("-")


def _basename(tok: str) -> str:
    name = os.path.basename(tok.replace("\\", "/")).lower()
    return name[:-4] if name.endswith(".exe") else name


def _opaque_in(text: str) -> bool:
    return bool(_OPAQUE_RE.search(text))


def _redirect_ops(words: List[str], cwd: Optional[str]) -> Tuple[List[str], List[Op]]:
    """Pull `> file` redirections out of a segment; return (remaining words, ops)."""
    ops: List[Op] = []
    rest: List[str] = []
    i = 0
    while i < len(words):
        w = words[i]
        if w in (">", ">|") and i + 1 < len(words):
            tgt = words[i + 1]
            i += 2
            if tgt.startswith("/dev/") or tgt == "&1" or tgt.isdigit():
                continue
            ops.append(Op(OVERWRITE, [tgt], cwd=cwd, detail="> redirect",
                          unresolved=_has_expansion(tgt)))
            continue
        if re.fullmatch(r"[0-9&]*>>?&?[0-9-]*", w) or w in (">>", ">&", "&>", "&>>", "<", "<<", "<<<"):
            # append / fd dup / input: skip the operator and (for file operators) its target
            i += 2 if w in (">>", "&>>", "<", "<<", "<<<") and i + 1 < len(words) else 1
            continue
        rest.append(w)
        i += 1
    return rest, ops


def _strip_wrappers(words: List[str]) -> Tuple[List[str], bool]:
    """Remove env assignments and wrappers (sudo, env, time ...). Returns (words, via_xargs)."""
    via_xargs = False
    i = 0
    while i < len(words):
        w = words[i]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w):
            i += 1
            continue
        b = _basename(w)
        if b in _WRAPPERS:
            i += 1
            # skip wrapper options (and the value of well-known value options)
            while i < len(words) and _is_flag(words[i]):
                if words[i] in ("-u", "-g", "-n", "-s", "-k", "-p", "-C") and b in ("sudo", "doas", "timeout"):
                    i += 1
                i += 1
            if b == "timeout" and i < len(words) and re.fullmatch(r"[0-9.]+[smhd]?", words[i]):
                i += 1
            continue
        if b == "xargs":
            via_xargs = True
            i += 1
            while i < len(words) and _is_flag(words[i]):
                if words[i] in ("-I", "-i", "-n", "-P", "-L", "-d", "-a"):
                    i += 1
                i += 1
            continue
        break
    return words[i:], via_xargs


def _positional(args: List[str], value_flags=()) -> List[str]:
    out: List[str] = []
    i = 0
    stop = False
    while i < len(args):
        a = args[i]
        if not stop and a == "--":
            stop = True
        elif not stop and _is_flag(a):
            if a in value_flags:
                i += 1
        else:
            out.append(a)
        i += 1
    return out


def _rm_op(name: str, args: List[str], cwd: Optional[str], via_xargs: bool) -> Op:
    recursive = any(
        a in ("-r", "-R", "--recursive") or (a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a))
        for a in args
    ) or name in ("rimraf", "rmdir_s")
    paths = _positional(args)
    flags = "".join(a for a in args if _is_flag(a))
    op = Op(DELETE, paths, cwd=cwd, recursive=recursive,
            detail=f"{name}{' -rf' if recursive and 'f' in flags else (' -r' if recursive else '')}")
    if via_xargs and not paths:
        op.unresolved = True
        op.detail += " (via xargs)"
    if any(_has_expansion(p) for p in paths):
        op.unresolved = True
    if not paths and not via_xargs:
        op.paths = []
    return op


def _analyze_segment(words: List[str], cwd: Optional[str], depth: int = 0) -> Tuple[List[Op], Optional[str]]:
    """Analyze one simple command. Returns (ops, possibly-updated cwd)."""
    ops: List[Op] = []
    words, redir_ops = _redirect_ops(words, cwd)
    ops.extend(redir_ops)
    words, via_xargs = _strip_wrappers(words)
    if not words:
        return ops, cwd

    name = _basename(words[0])
    args = words[1:]

    if name == "cd" and args:
        tgt = [a for a in args if not _is_flag(a)]
        if tgt and not _has_expansion(tgt[0]) and tgt[0] != "-":
            base = cwd
            cwd = tgt[0] if (os.path.isabs(tgt[0]) or tgt[0].startswith("~") or base is None) \
                else os.path.join(base, tgt[0])
        return ops, cwd

    if name in _SHELLS and depth < 3:
        for idx, a in enumerate(args):
            if a in ("-c", "-lc", "-ic", "-Command", "-command", "-c") and idx + 1 < len(args):
                ops.extend(analyze_command(args[idx + 1], cwd=cwd, _depth=depth + 1))
                break
        return ops, cwd

    if name in _RM_LIKE:
        if name == "rmdir" and any(a.lower() in ("/s", "/q") for a in args):
            args = [a for a in args if not a.startswith("/")] + ["-r"]
        ops.append(_rm_op(name, args, cwd, via_xargs))
    elif name in _WIN_DEL:
        paths = [a for a in args if not a.startswith("/")]
        ops.append(Op(DELETE, paths, cwd=cwd, detail=name,
                      recursive=any(a.lower() == "/s" for a in args)))
    elif name in _WIN_RD:
        paths = [a for a in args if not a.startswith("/")]
        ops.append(Op(DELETE, paths, cwd=cwd, detail=name,
                      recursive=any(a.lower() == "/s" for a in args)))
    elif name in _PS_REMOVE:
        paths: List[str] = []
        recursive = False
        j = 0
        while j < len(args):
            a = args[j]
            if a.lower() in ("-recurse", "-r"):
                recursive = True
            elif a.lower() in ("-path", "-literalpath") and j + 1 < len(args):
                paths.append(args[j + 1])
                j += 1
            elif not _is_flag(a):
                paths.append(a)
            j += 1
        ops.append(Op(DELETE, paths, cwd=cwd, recursive=recursive, detail="Remove-Item"))
    elif name in ("mv", "cp", "install", "ln", "rsync"):
        pos = _positional(args, value_flags=("-t", "--target-directory", "-S", "-e", "--exclude"))
        noclobber = any(a in ("-n", "--no-clobber") for a in args)
        if len(pos) >= 2 and not noclobber and name != "ln":
            ops.append(Op(OVERWRITE, [pos[-1]], cwd=cwd, detail=f"{name} onto destination",
                          recursive=any(a in ("-r", "-R", "-a", "--recursive") for a in args),
                          git_flags=tuple(pos[:-1])))   # sources, used to compute dest names
        elif name == "ln" and any(a in ("-f", "--force", "-sf", "-fs") for a in args) and len(pos) >= 2:
            ops.append(Op(OVERWRITE, [pos[-1]], cwd=cwd, detail="ln -f onto destination"))
        if name == "rsync" and any(a == "--delete" or a.startswith("--delete-") for a in args) and len(pos) >= 2:
            ops.append(Op(DELETE, [pos[-1]], cwd=cwd, recursive=True, upper_bound=True,
                          detail="rsync --delete (removes files absent from source)"))
    elif name == "sed":
        inplace = any(a == "--in-place" or a.startswith("--in-place=") or
                      (a.startswith("-") and not a.startswith("--") and "i" in a[1:] and not a.startswith("-e"))
                      for a in args)
        if inplace:
            has_script_flag = any(a in ("-e", "-f", "--expression", "--file") for a in args)
            pos = _positional(args, value_flags=("-e", "-f", "--expression", "--file"))
            files = pos if has_script_flag else pos[1:]
            if files:
                ops.append(Op(INPLACE, files, cwd=cwd, detail="sed -i"))
    elif name == "perl":
        if any(a.startswith("-") and not a.startswith("--") and "i" in a[1:] and "e" not in a[:2] for a in args):
            files = _positional(args, value_flags=("-e", "-E"))
            if files:
                ops.append(Op(INPLACE, files, cwd=cwd, detail="perl -i"))
    elif name == "tee":
        if not any(a in ("-a", "--append") for a in args):
            files = [a for a in _positional(args) if not a.startswith("/dev/")]
            if files:
                ops.append(Op(OVERWRITE, files, cwd=cwd, detail="tee (truncates)"))
    elif name == "truncate":
        files = _positional(args, value_flags=("-s", "--size", "-r", "--reference"))
        if files:
            ops.append(Op(TRUNCATE, files, cwd=cwd, detail="truncate"))
    elif name == "dd":
        for a in args:
            if a.startswith("of="):
                tgt = a[3:]
                if tgt.startswith("/dev/") and not tgt.startswith(("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty")):
                    ops.append(Op(DISK, [tgt], cwd=cwd, detail="dd to a device"))
                elif not tgt.startswith("/dev/"):
                    ops.append(Op(OVERWRITE, [tgt], cwd=cwd, detail="dd of=", unresolved=_has_expansion(tgt)))
    elif name.startswith(_FS_FORMAT_PREFIX) or name in ("wipefs", "fdisk", "parted", "diskpart", "format"):
        ops.append(Op(DISK, list(_positional(args)), cwd=cwd, detail=name))
    elif name == "find":
        roots: List[str] = []
        for a in args:
            if a.startswith("-") or a in ("(", "!", ")"):
                break
            roots.append(a)
        roots = roots or ["."]
        text = " ".join(args)
        if "-delete" in args or re.search(r"-exec(dir)?\s+(rm|unlink|shred)\b", text):
            ops.append(Op(DELETE, roots, cwd=cwd, recursive=True, upper_bound=bool(re.search(r"-(i?name|regex|type|mtime|size|newer)", text)),
                          detail="find -delete"))
    elif name == "git":
        op = _git_op(args, cwd)
        if op:
            ops.append(op)
    elif name in ("python", "python3", "py", "node", "deno", "bun", "ruby", "perl", "php", "pwsh", "powershell", "nu"):
        joined = " ".join(args)
        if _opaque_in(joined):
            ops.append(Op(OPAQUE, [], cwd=cwd, unresolved=True, detail=f"{name} code that deletes files"))
    return ops, cwd


def _git_op(args: List[str], cwd: Optional[str]) -> Optional[Op]:
    git_dir = cwd
    i = 0
    while i < len(args) and _is_flag(args[i]):
        if args[i] == "-C" and i + 1 < len(args):
            git_dir = args[i + 1] if (os.path.isabs(args[i + 1]) or cwd is None) else os.path.join(cwd, args[i + 1])
            i += 1
        elif args[i] == "-c":
            i += 1
        i += 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]
    flags = tuple(a for a in rest if _is_flag(a))
    paths = [a for a in rest if not _is_flag(a)]
    if sub == "reset" and "--hard" in rest:
        return Op(GIT_DISCARD, [], cwd=cwd, git_dir=git_dir, detail="git reset --hard", git_flags=flags)
    if sub == "clean":
        letters = "".join(f.lstrip("-") for f in flags if not f.startswith("--"))
        if "n" in letters or "--dry-run" in flags:
            return None
        if "f" in letters or "--force" in flags:
            return Op(GIT_CLEAN, paths, cwd=cwd, git_dir=git_dir, detail="git clean " + " ".join(flags),
                      git_flags=flags, exclude_untracked_ignored=("x" not in letters))
        return None
    if sub == "checkout":
        if "--" in rest or "." in paths or "-f" in flags or "--force" in flags:
            specific = [p for p in rest[rest.index("--") + 1:]] if "--" in rest else [p for p in paths if p == "."]
            return Op(GIT_DISCARD, specific, cwd=cwd, git_dir=git_dir, detail="git checkout (discard changes)", git_flags=flags)
    if sub == "restore":
        if "--staged" in rest and "--worktree" not in rest and "-W" not in rest:
            return None
        return Op(GIT_DISCARD, paths, cwd=cwd, git_dir=git_dir, detail="git restore (discard changes)", git_flags=flags)
    return None


def analyze_command(command: str, cwd: Optional[str] = None, _depth: int = 0) -> List[Op]:
    """Return destructive operations in a shell command line. Never raises."""
    try:
        if not command or not command.strip():
            return []
        text = _newlines_to_semicolons(_strip_heredocs(command))
        tokens = _tokenize(text)
        if tokens is None:
            return []
        ops: List[Op] = []
        cur = cwd
        for seg in _split_segments(tokens):
            seg_ops, cur = _analyze_segment(seg, cur, _depth)
            ops.extend(seg_ops)
        return ops
    except Exception:
        return []


def analyze_patch(patch_text: str) -> List[Op]:
    """V4A patch bodies: '*** Delete File: path' and '*** Move File: a -> b'."""
    ops: List[Op] = []
    for m in re.finditer(r"^\*\*\* Delete File:\s*(.+?)\s*$", patch_text or "", re.M):
        ops.append(Op(DELETE, [m.group(1)], detail="patch: Delete File"))
    for m in re.finditer(r"^\*\*\* Move File:\s*.+?->\s*(.+?)\s*$", patch_text or "", re.M):
        ops.append(Op(OVERWRITE, [m.group(1)], detail="patch: Move File onto destination"))
    return ops
