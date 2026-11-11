import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_plugin():
    spec = importlib.util.spec_from_file_location(
        "blast_radius", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["blast_radius"] = mod
    spec.loader.exec_module(mod)
    return mod


_load_plugin()


@pytest.fixture(autouse=True)
def hermes_home(tmp_path, monkeypatch):
    home = tmp_path / "hermes_home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


@pytest.fixture
def repo(tmp_path):
    """A git repo with: tracked clean files, 2 dirty tracked files, untracked notes, ignored build dir, a .env."""
    r = tmp_path / "proj"
    (r / "src").mkdir(parents=True)
    (r / "build").mkdir()
    git(r, "init", "-q")
    (r / ".gitignore").write_text("build/\n.env\n")
    for i in range(6):
        (r / "src" / f"m{i}.py").write_text(f"print({i})\n" * 5)
    (r / "README.md").write_text("hi\n")
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "init")
    (r / "src" / "m0.py").write_text("print('edited')\n")        # dirty
    (r / "src" / "m1.py").write_text("print('edited too')\n")    # dirty
    (r / "notes.txt").write_text("my precious notes\n")           # untracked
    for i in range(30):
        (r / "build" / f"o{i}.o").write_text("x" * 100)           # ignored
    (r / ".env").write_text("TOKEN=abc\n")                        # ignored secret
    return r
