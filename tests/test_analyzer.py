import blast_radius.analyzer as A


def kinds(cmd):
    return [(o.kind, o.paths, o.recursive, o.unresolved) for o in A.analyze_command(cmd)]


def test_rm_rf():
    assert kinds("rm -rf build/ dist") == [("delete", ["build/", "dist"], True, False)]


def test_rm_plain_not_recursive():
    assert kinds("rm a.txt")[0][2] is False


def test_compound_and_cd():
    ops = A.analyze_command("cd sub && rm -rf out; ls")
    assert ops[0].kind == "delete" and ops[0].cwd == "sub"


def test_sudo_and_env_wrappers():
    assert kinds("sudo -u bob env FOO=1 rm -rf x")[0][:2] == ("delete", ["x"])


def test_bash_c_recurses():
    assert kinds("bash -c 'rm -rf data'")[0][:2] == ("delete", ["data"])


def test_unresolved_variable():
    assert kinds("rm -rf $BUILD_DIR/*")[0][3] is True


def test_xargs_rm_unresolved():
    ops = A.analyze_command("git ls-files | xargs rm")
    assert ops and ops[0].unresolved


def test_redirect_truncate_vs_append():
    assert kinds("echo hi > out.txt")[0][:2] == ("overwrite", ["out.txt"])
    assert kinds("echo hi >> out.txt") == []
    assert kinds("make 2>&1 > /dev/null") == []


def test_devnull_ignored():
    assert kinds("cmd > /dev/null 2>&1") == []


def test_mv_cp_destination():
    ops = A.analyze_command("mv a.txt b.txt")
    assert ops[0].kind == "overwrite" and ops[0].paths == ["b.txt"] and ops[0].git_flags == ("a.txt",)
    assert A.analyze_command("cp -n a b") == []


def test_sed_inplace():
    assert kinds("sed -i 's/a/b/' f1 f2")[0][:2] == ("inplace", ["f1", "f2"])
    assert kinds("sed 's/a/b/' f1") == []


def test_tee():
    assert kinds("echo x | tee out.log")[0][:2] == ("overwrite", ["out.log"])
    assert kinds("echo x | tee -a out.log") == []


def test_find_delete():
    o = A.analyze_command("find . -name '*.pyc' -delete")[0]
    assert o.kind == "delete" and o.upper_bound and o.paths == ["."]


def test_git_ops():
    assert A.analyze_command("git reset --hard HEAD~1")[0].kind == "git_discard"
    assert A.analyze_command("git clean -fdx")[0].exclude_untracked_ignored is False
    assert A.analyze_command("git clean -n") == []
    assert A.analyze_command("git checkout -- .")[0].kind == "git_discard"
    assert A.analyze_command("git restore --staged f") == []
    assert A.analyze_command("git status") == []


def test_opaque_python():
    o = A.analyze_command("python -c \"import shutil; shutil.rmtree('x')\"")[0]
    assert o.kind == "opaque" and o.unresolved


def test_heredoc_body_is_not_a_command():
    assert A.analyze_command("cat > f.txt <<'EOF'\nrm -rf /\nEOF") [0].kind == "overwrite"
    assert not any(o.kind == "delete" for o in A.analyze_command("cat > f.txt <<'EOF'\nrm -rf /\nEOF"))


def test_newline_separates_commands():
    assert any(o.kind == "delete" for o in A.analyze_command("ls\nrm -rf x"))


def test_quoted_semicolon_not_split():
    assert A.analyze_command("echo 'a; rm -rf x'") == []


def test_garbage_never_raises():
    assert A.analyze_command("echo 'unterminated") == []
    assert A.analyze_command("") == []
    assert A.analyze_command(None) == []


def test_patch_delete_file():
    ops = A.analyze_patch("*** Begin Patch\n*** Delete File: a/b.py\n*** End Patch")
    assert ops[0].kind == "delete" and ops[0].paths == ["a/b.py"]


def test_windows_commands():
    assert A.analyze_command("Remove-Item -Recurse -Force build")[0].recursive
    assert A.analyze_command("del /q a.txt")[0].kind == "delete"
