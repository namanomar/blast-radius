# blast-radius

**Approval prompts that tell you what will actually be destroyed.**

Hermes asks "allow `rm -rf src`?" and you have to guess. blast-radius measures the real
filesystem and git state first, then answers the question that matters:

```
BLAST RADIUS  [#########-----------] ELEVATED 43/100
  rm -rf src notes.txt
  3 file(s), 1 dir(s), 17 B
  !  1 file(s) with UNCOMMITTED changes: src/a.py
  !  1 file(s) not in git, no other copy: notes.txt
     recoverable: 1 tracked-clean (git checkout), 0 git-ignored (regenerable)
  Safety net: capsule bx-1111-183236-09be holds 2 irreplaceable file(s) (15 B)
  Undo after the fact: /blast restore bx-1111-183236-09be   (or: /blast undo)
  Why 43: 1 file(s) with UNCOMMITTED git changes (+32), 1 file(s) not in git (+9), 3 file(s) affected (+2)
```

It is a **policy plugin, not a prompt or a skill**: it sits on `pre_tool_call` and
`post_tool_call`, so it works on every model, every platform and every turn, whether or not the
model remembers to be careful.

## What it does

| Situation | What happens |
|---|---|
| `rm -rf build/` (git-ignored, regenerable) | **Silent.** No nagging for harmless cleanup. |
| `rm -rf src/` with uncommitted edits | **Approval prompt** with the exact files at risk, plus a recovery capsule. |
| `git reset --hard`, `git clean -fdx` | Counts the dirty / untracked / ignored files it would really discard. |
| `rm -rf ~`, `rm -rf .git`, `dd of=/dev/sda`, deleting Hermes' own data | **Blocked**, with a message that tells the model how to narrow it. |
| `rm -rf $DIR`, `xargs rm`, `python -c "shutil.rmtree(...)"` | Targets are unknowable, so it **escalates** instead of guessing. |
| `write_file` that shrinks a 300-line file to 1 line | **Escalated** (the classic "agent truncated my file"). |
| Command ran, then you regret it | `/blast undo`. Never overwrites edits made after the capsule. |

Every point of the 0-100 score comes with a reason, so you can see *why* before you click.

### Things a regex guard cannot do

* **Measures, doesn't pattern-match.** It globs the paths, walks the tree and asks git
  (`git status --porcelain -z --ignored`) which files are clean, modified, untracked or ignored.
* **Back-ups only what matters.** Files clean in git are one `git checkout` away, so capsules hold
  just uncommitted work, untracked files and credentials. They stay tiny.
* **Closes the loop.** `post_tool_call` checks whether the command really changed anything; if you
  denied it (or it failed) the capsule is dropped automatically.
* **Understands shell.** Quote-aware tokenizer; `cd x && rm`, `sudo`/`env`/`time` wrappers,
  `bash -c '...'`, heredocs (their bodies are *not* commands), globs, `~`, redirects, `tee`,
  `sed -i`, `find -delete`, `mv`/`cp` onto existing files, PowerShell `Remove-Item`, `del`, V4A
  patch `*** Delete File`.
* **Fails open.** An internal error never blocks the agent; unparseable commands pass through.

### For the agent itself

* `blast_radius` tool: the model can **preview** a command before running it, learn the score, and
  narrow the scope instead of getting blocked.
* `blast_restore` tool: the model can undo its own mistake. It cannot force-overwrite newer edits;
  only a human can (`/blast restore <id> --force`).

## Commands

```
/blast                       status, savings, recent decisions
/blast explain rm -rf build  preview a command's blast radius (runs nothing)
/blast undo                  restore the newest capsule from a command that really ran
/blast restore <id> [--force]
/blast list | /blast stats
hermes blast ...             the same, from the terminal
```

## Install

```
hermes plugins install <owner>/blast-radius
hermes plugins enable blast-radius
```

## Configuration (`plugins.entries.blast-radius.settings`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | master switch |
| `mode` | `enforce` | `advise` never blocks on score (critical targets such as `.git` or `~` are always blocked) |
| `approve_score` | `40` | score that forces the approval prompt |
| `block_score` | `90` | score that blocks (enforce mode) |
| `capsules` | `true` | take recovery capsules |
| `capsule_max_mb` / `capsule_keep` / `capsule_days` | `200` / `200` / `14` | capsule limits |

## Disclosure (what this plugin touches)

* **Network:** none. No telemetry, no credentials read or stored.
* **Subprocesses:** `git rev-parse --show-toplevel` and `git status --porcelain=v1 -z -uall
  --ignored=traditional`, run read-only (argv lists, `GIT_OPTIONAL_LOCKS=0`, hard timeouts) in the
  directories a pending command would affect. No other processes are started.
* **Files read:** only the targets of a pending destructive command (names, sizes, git state; file
  contents only when copying into a capsule).
* **Files written:** `<HERMES_HOME>/plugin-data/blast-radius/` (capsules, `ledger.jsonl`), and, only
  when you run `/blast restore`/`undo` (or the agent calls `blast_restore`), the original paths of
  captured files. Restore refuses to overwrite files that changed after the capsule.
* **Stored data:** the ledger keeps each assessed command (truncated to 300 chars, with
  `token=`/`key=`/`password=` style values masked) and its score. Capsules contain copies of the
  files they protect, so treat the plugin-data directory like the files themselves; capsules are
  pruned after 14 days / 200 entries by default.
* **Limits (be honest about them):** the analyzer sees shell text, not intent. A script that deletes
  things internally (`./cleanup.sh`) is invisible until it runs; tools other than `terminal`,
  `execute_code`, `write_file` and `patch` are not watched; capsules cap at 200 MB per command.
  It complements, and does not replace, Hermes' own approval gate and sandboxing.

## Development

```
cd tests && python -m pytest -q          # 58 tests, real git repos in temp dirs
hermes plugins validate . --install-deps
hermes plugins doctor . --ci
```

MIT licensed.
