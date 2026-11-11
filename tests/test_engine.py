import json
import shutil
from pathlib import Path

import blast_radius as P
import blast_radius.capsule as C
import blast_radius.engine as E
import blast_radius.ledger as L
from blast_radius.policy import Config, ALLOW, APPROVE, BLOCK


class FakeCtx:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.hooks, self.tools, self.commands = {}, {}, {}

    def get_config(self, key, default=None):
        return self.cfg.get(key, default)

    def register_hook(self, name, cb, **kw):
        self.hooks[name] = cb

    def register_tool(self, name, toolset, schema, handler, **kw):
        self.tools[name] = handler

    def register_command(self, name, handler, **kw):
        self.commands[name] = handler

    def register_cli_command(self, **kw):
        pass


def setup_plugin(cfg=None):
    ctx = FakeCtx(cfg)
    P.register(ctx)
    return ctx


def terminal(repo, cmd):
    return {"command": cmd, "workdir": str(repo)}


# ---------------------------------------------------------------- measurement


def test_rm_ignored_build_dir_is_silent(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf build"), Config())
    assert a.impact.files == 30 and a.impact.ignored == 30
    assert a.impact.dirty == [] and a.impact.untracked == []
    assert a.verdict.action == ALLOW          # regenerable build output must not nag


def test_rm_src_flags_uncommitted_work(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf src"), Config())
    assert len(a.impact.dirty) == 2
    assert a.verdict.action == APPROVE
    assert any("UNCOMMITTED" in w for _, w in a.verdict.reasons)
    assert len(a.impact.at_risk) == 2          # only the two files git cannot bring back


def test_untracked_notes_scored(repo):
    a = E.assess_call("terminal", terminal(repo, "rm notes.txt"), Config())
    assert a.impact.untracked and a.verdict.score > 0


def test_secret_detected(repo):
    a = E.assess_call("terminal", terminal(repo, "rm .env"), Config())
    assert len(a.impact.secrets) == 1 and a.impact.at_risk


def test_git_reset_hard_counts_dirty(repo):
    a = E.assess_call("terminal", terminal(repo, "git reset --hard"), Config())
    assert len(a.impact.dirty) == 2 and a.verdict.action == APPROVE


def test_git_clean_fdx_counts_untracked_and_ignored(repo):
    a = E.assess_call("terminal", terminal(repo, "git clean -fdx"), Config())
    assert a.impact.files >= 32          # notes + 30 build objects + .env
    assert a.impact.secrets


def test_git_clean_dry_run_ignored(repo):
    assert E.assess_call("terminal", terminal(repo, "git clean -n"), Config()) is None


def test_mv_over_existing_file(repo):
    a = E.assess_call("terminal", terminal(repo, "mv notes.txt src/m0.py"), Config())
    assert a.impact.files == 1 and a.impact.dirty


def test_redirect_overwrite_of_dirty_file(repo):
    a = E.assess_call("terminal", terminal(repo, "echo x > src/m0.py"), Config())
    assert a.impact.dirty and a.impact.at_risk


def test_nonexistent_target_is_nothing(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf nope"), Config())
    assert a.impact.files == 0 and a.verdict.action == ALLOW


def test_glob_expansion(repo):
    a = E.assess_call("terminal", terminal(repo, "rm src/*.py"), Config())
    assert a.impact.files == 6


def test_safe_command_returns_none(repo):
    assert E.assess_call("terminal", terminal(repo, "ls -la && git status"), Config()) is None


# ---------------------------------------------------------------- critical / protected


def test_rm_rf_home_blocked(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf ~"), Config())
    assert a.verdict.action == BLOCK and a.verdict.tier == "CRITICAL"


def test_rm_rf_root_blocked(repo):
    root = Path(repo.anchor).as_posix()
    a = E.assess_call("terminal", terminal(repo, f"rm -rf {root}"), Config())
    assert a.verdict.action == BLOCK


def test_rm_dot_git_blocked(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf .git"), Config())
    assert a.verdict.action == BLOCK and any(".git" in c for c in a.verdict.critical)


def test_advise_mode_still_blocks_critical(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf .git"), Config(mode="advise"))
    assert a.verdict.action == BLOCK


def test_hermes_home_is_protected(repo, hermes_home):
    a = E.assess_call("terminal", terminal(repo, f"rm -rf {hermes_home.as_posix()}"), Config())
    assert a.verdict.action == BLOCK


def test_dd_to_device_blocked(repo):
    a = E.assess_call("terminal", terminal(repo, "dd if=/dev/zero of=/dev/sda"), Config())
    assert a.verdict.action == BLOCK


def test_unresolved_variable_escalates(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf $TARGET"), Config())
    assert a.verdict.action == APPROVE


# ---------------------------------------------------------------- write_file / patch


def test_write_file_shrink_triggers_approval(repo):
    big = repo / "big.py"
    big.write_text("line\n" * 300)
    a = E.assess_call("write_file", {"path": str(big), "content": "x\n"}, Config())
    assert a.impact.shrink == (300, 1) and a.verdict.action == APPROVE


def test_write_file_normal_edit_is_silent(repo):
    a = E.assess_call("write_file", {"path": str(repo / "src" / "m3.py"), "content": "print(3)\n" * 5}, Config())
    assert a is None or a.verdict.action == ALLOW


def test_new_file_write_ignored(repo):
    assert E.assess_call("write_file", {"path": str(repo / "brand_new.txt"), "content": "x"}, Config()) is None


def test_v4a_patch_delete(repo):
    body = "*** Begin Patch\n*** Delete File: notes.txt\n*** End Patch"
    a = E.assess_call("patch", {"patch": body, "workdir": str(repo)}, Config())
    assert a.impact.untracked


# ---------------------------------------------------------------- capsules


def test_capsule_roundtrip_and_refuses_newer_edits(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf src notes.txt"), Config())
    m = E.make_capsule(a, Config())
    assert m and len(m["entries"]) == 3          # 2 dirty + 1 untracked, not the 4 clean files
    shutil.rmtree(repo / "src")
    (repo / "notes.txt").unlink()
    restored, same, refused = C.restore(m["id"])
    assert len(restored) == 3 and not refused
    assert (repo / "notes.txt").read_text() == "my precious notes\n"
    assert (repo / "src" / "m0.py").read_text() == "print('edited')\n"
    # edit after the capsule: restore must refuse; force must keep a backup of what it replaces
    (repo / "notes.txt").write_text("newer\n")
    restored, same, refused = C.restore(m["id"])
    assert refused and (repo / "notes.txt").read_text() == "newer\n"
    restored, same, refused = C.restore(m["id"], force=True)
    assert (repo / "notes.txt").read_text() == "my precious notes\n"
    assert list((C._root() / m["id"] / "replaced").iterdir())


def test_capsule_size_cap_marks_partial(repo):
    big = repo / "big.bin"
    big.write_bytes(b"0" * (2 * 1024 * 1024))
    a = E.assess_call("terminal", terminal(repo, "rm big.bin notes.txt"), Config())
    m = E.make_capsule(a, Config(capsule_max_mb=1))
    assert m["partial"] and m["skipped"] == 1
    assert any("too large to fully back up" in w for _, w in a.verdict.reasons)


def test_no_capsule_when_everything_is_in_git(repo):
    a = E.assess_call("terminal", terminal(repo, "rm src/m4.py"), Config())
    assert E.make_capsule(a, Config()) is None


# ---------------------------------------------------------------- hook end to end


def test_hook_approves_with_report_and_capsule(repo):
    ctx = setup_plugin()
    r = ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf src"), task_id="t")
    assert r["action"] == "approve"
    assert "BLAST RADIUS" in r["message"] and "UNCOMMITTED" in r["message"] and "/blast restore bx-" in r["message"]


def test_hook_blocks_with_actionable_message(repo):
    ctx = setup_plugin()
    r = ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf ~"), task_id="t")
    assert r["action"] == "block" and "Narrow" in r["message"]


def test_hook_silent_for_harmless_and_unwatched(repo):
    ctx = setup_plugin()
    assert ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "ls"), task_id="t") is None
    assert ctx.hooks["pre_tool_call"](tool_name="web_search", args={"q": "x"}, task_id="t") is None
    assert ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf build"), task_id="t") is None


def test_hook_fails_open_on_internal_error(repo, monkeypatch):
    ctx = setup_plugin()

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(P, "assess_call", boom)
    assert ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf src"), task_id="t") is None


def test_disabled_config_is_inert(repo):
    ctx = setup_plugin({"enabled": False})
    assert ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf .git"), task_id="t") is None


def test_post_hook_drops_capsule_when_command_did_nothing(repo):
    ctx = setup_plugin()
    args = terminal(repo, "rm -rf src")
    ctx.hooks["pre_tool_call"](tool_name="terminal", args=args, task_id="t", tool_call_id="c1")
    assert C.list_capsules()
    ctx.hooks["post_tool_call"](tool_name="terminal", args=args, result="denied", tool_call_id="c1")
    assert C.list_capsules() == []
    assert L.stats()["nothing_happened"] == 1


def test_undo_after_real_execution(repo):
    ctx = setup_plugin()
    args = terminal(repo, "rm -rf src notes.txt")
    ctx.hooks["pre_tool_call"](tool_name="terminal", args=args, task_id="t", tool_call_id="c2")
    shutil.rmtree(repo / "src")
    (repo / "notes.txt").unlink()                                        # the command "runs"
    ctx.hooks["post_tool_call"](tool_name="terminal", args=args, result="ok", tool_call_id="c2")
    out = ctx.commands["blast"]("undo")
    assert "restored 3 file(s)" in out
    assert (repo / "notes.txt").exists() and (repo / "src" / "m0.py").exists()
    assert L.stats()["restores"] == 1


# ---------------------------------------------------------------- tools and commands


def test_blast_radius_tool_preview(repo, monkeypatch):
    ctx = setup_plugin()
    monkeypatch.chdir(repo)
    out = json.loads(ctx.tools["blast_radius"]({"command": "rm -rf src"}))
    assert out["action"] == "approve" and out["uncommitted_changes"] == 2
    assert json.loads(ctx.tools["blast_radius"]({"command": "ls"}))["action"] == "allow"
    assert "error" in json.loads(ctx.tools["blast_radius"]({}))


def test_blast_restore_tool_unknown_capsule(repo):
    ctx = setup_plugin()
    assert "error" in json.loads(ctx.tools["blast_restore"]({"capsule_id": "bx-nope"}))


def test_explain_and_stats_commands(repo, monkeypatch):
    ctx = setup_plugin()
    monkeypatch.chdir(repo)
    assert "BLAST RADIUS" in ctx.commands["blast"]("explain rm -rf src")
    assert "blast-radius counters" in ctx.commands["blast"]("stats")
    assert "blast-radius active" in ctx.commands["blast"]("")
    assert "usage" in ctx.commands["blast"]("restore")


def test_secrets_redacted_in_ledger(repo):
    L.record({"type": "decision", "cmd": "curl -H 'Authorization: bearer sk-abcdef' --token=hunter2"})
    assert "hunter2" not in json.dumps(L.read())


def test_undo_works_even_if_post_hook_never_fired(repo):
    ctx = setup_plugin()
    args = terminal(repo, "rm -rf src notes.txt")
    ctx.hooks["pre_tool_call"](tool_name="terminal", args=args, task_id="t")   # no post_tool_call
    assert "Nothing to undo" in ctx.commands["blast"]("undo")                  # nothing destroyed yet
    shutil.rmtree(repo / "src")
    (repo / "notes.txt").unlink()
    assert "restored 3 file(s)" in ctx.commands["blast"]("undo")


# ---------------------------------------------------------------- strict mode (fail closed)


def test_strict_blocks_unparseable_but_default_fails_open(repo):
    cmd = terminal(repo, "rm -rf 'src")                       # unbalanced quote
    assert E.assess_call("terminal", cmd, Config()) is None   # default: fail open, as documented
    a = E.assess_call("terminal", cmd, Config(strict=True))
    assert a.verdict.action == BLOCK and a.verdict.tier == "UNMEASURABLE" and "cannot be parsed" in a.verdict.unmeasurable


def test_strict_blocks_unknowable_targets(repo):
    assert E.assess_call("terminal", terminal(repo, "rm -rf $TARGET"), Config()).verdict.action == APPROVE
    for cmd in ("rm -rf $TARGET", "git ls-files | xargs rm", 'python -c "import shutil; shutil.rmtree(p)"'):
        a = E.assess_call("terminal", terminal(repo, cmd), Config(strict=True))
        assert a.verdict.action == BLOCK and a.verdict.unmeasurable, cmd


def test_strict_reaches_inside_bash_c(repo):
    cmd = terminal(repo, "bash -c \"rm -rf 'src\"")
    assert E.assess_call("terminal", cmd, Config()) is None
    assert E.assess_call("terminal", cmd, Config(strict=True)).verdict.action == BLOCK


def test_strict_overrides_advise_mode(repo):
    a = E.assess_call("terminal", terminal(repo, "rm -rf $TARGET"), Config(strict=True, mode="advise"))
    assert a.verdict.action == BLOCK


def test_strict_does_not_over_block_measurable_commands(repo):
    cfg = Config(strict=True)
    assert E.assess_call("terminal", terminal(repo, "ls -la"), cfg) is None
    assert E.assess_call("terminal", terminal(repo, "rm -rf build"), cfg).verdict.action == ALLOW
    assert E.assess_call("terminal", terminal(repo, "rm -rf src"), cfg).verdict.action == APPROVE
    assert E.assess_call("terminal", terminal(repo, "rm -rf .git"), cfg).verdict.tier == "CRITICAL"


def test_strict_flag_does_not_leak_between_calls(repo):
    E.assess_call("terminal", terminal(repo, "rm -rf 'src"), Config(strict=True))
    assert E.assess_call("terminal", terminal(repo, "rm -rf 'src"), Config()) is None


def test_hook_strict_block_message_tells_the_model_how_to_fix(repo):
    ctx = setup_plugin({"strict": True})
    r = ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "rm -rf $TARGET"), task_id="t")
    assert r["action"] == "block"
    assert "strict mode" in r["message"] and "explicit literal paths" in r["message"]


def test_hook_strict_fails_closed_on_internal_error(repo, monkeypatch):
    ctx = setup_plugin({"strict": True})

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(P, "assess_call", boom)
    r = ctx.hooks["pre_tool_call"](tool_name="terminal", args=terminal(repo, "ls"), task_id="t")
    assert r["action"] == "block" and "strict mode" in r["message"]
    assert ctx.hooks["pre_tool_call"](tool_name="web_search", args={}, task_id="t") is None   # unwatched tools untouched
