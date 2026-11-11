#!/usr/bin/env bash
# Builds a realistic "oh no" project for the blast-radius demo in ./demo-project
set -e
rm -rf demo-project && mkdir -p demo-project/src demo-project/build && cd demo-project
git init -q && git config user.email demo@example.com && git config user.name demo
printf 'build/\n.env\n' > .gitignore
for f in app db auth api utils; do printf "def %s():\n    return '%s'\n" "$f" "$f" > "src/$f.py"; done
echo "# demo" > README.md
git add -A && git commit -qm "initial commit"
# the work that exists nowhere else:
printf "def auth():\n    # WIP: rewriting token refresh\n    return 'new-auth-flow'\n" > src/auth.py
printf "def api():\n    return 'half-finished endpoint'\n" > src/api.py
printf "interview notes - do not lose\nask about the migration plan\n" > notes.txt
echo "STRIPE_KEY=sk_test_demo" > .env
for i in $(seq 1 40); do head -c 2048 /dev/urandom > "build/obj$i.o"; done
echo "demo-project ready: 2 files with uncommitted edits, 1 untracked notes file, 1 secret, 40 build artifacts"
