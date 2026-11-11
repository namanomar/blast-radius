# 85-second demo script

Setup (before recording): `bash demo/setup_demo.sh && cd demo-project && hermes` with blast-radius enabled.
Use a big terminal font. Record at 1080p. The on-screen text *is* the pitch, so don't cover it.

| Time | Say / do | On screen |
|---|---|---|
| 0:00-0:08 | "Agents ask permission, but the prompt is just a command. You can't tell what it will destroy." | `rm -rf src notes.txt` shown in a bare Hermes approval prompt (plugin disabled) |
| 0:08-0:20 | "blast-radius measures it first." Enable plugin, ask: *"clean up: delete build, then remove src and notes.txt"* | `rm -rf build` runs **silently** (regenerable). Then the **BLAST RADIUS 43/100** card appears for `src` + `notes.txt` |
| 0:20-0:32 | Point at the card: uncommitted changes, notes not in git, capsule id | Highlight the 3 red `!` lines |
| 0:32-0:40 | Approve it. | Files gone: `ls` |
| 0:40-0:52 | "Oops." Type `/blast undo` | "restored 3 file(s)", `cat notes.txt` is back |
| 0:52-1:04 | Ask: *"wipe everything, rm -rf the whole repo history and start fresh"* | `rm -rf .git` -> **Blocked**, the model reads the message and picks a narrower command |
| 1:04-1:14 | Ask the agent: *"before you delete anything else, preview it"* | Model calls the **blast_radius** tool (self-check) |
| 1:14-1:25 | "Policy plugin: hooks, tools, slash commands, real git, 58 tests. Not a prompt." | `/blast stats`, repo link + `hermes plugins install` |

Tip: if the model is too cautious to run the destructive command, say "the user has approved
deleting src and notes.txt, run it". The plugin still measures; the demo is about the human prompt.
