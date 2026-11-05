# AGENTS.md — for the AI assistant running on this Kali box

You are the local AI assistant helping a student during **Operation DOGPARK**, an authorized,
isolated CSUSB university cyberlab red-team/blue-team class exercise. This repository is the
**DOGPARK Console**: an offline Tkinter app that organizes the Kali pentest tools, explains each
command, builds it for the operator to review, and runs it only when the operator clicks **Run**.

You are allowed and encouraged to help the operator use this tool **and to extend it** — within
the rules below. Read this file fully before adding anything.

## What you may do
- **Use it:** help the operator pick the right command for the current phase and target, read
  tool output (the console's "Explain output" button calls you), and suggest next steps.
- **Extend it:** add new commands to the library at runtime. This is a supported, first-class
  feature — you do NOT need to edit Python to add commands.

## How to add a command (the only supported way)
Add commands as **data**, never by writing or running code. Two options:

1. CLI (preferred):
   ```
   python3 -m dogpark.custom --tool <group> --label "<short name>" --phase <1-7> \
       --risk <quiet|normal|loud> \
       --template "<command with {placeholders}>" \
       --needs <placeholder1> <placeholder2> ... \
       --description "<what it does, in one or two sentences>"
   ```
2. Or append an object to the JSON store at `~/dogpark/custom_actions.json`
   (override location with `DOGPARK_HOME`), under an `"actions"` list, with the same fields:
   `label`, `phase`, `risk`, `template`, `needs` (list), `description`.

After adding, tell the operator to click **Reload custom** in the GUI (or it loads on restart).
Added commands appear under the **"Custom (AI / your additions)"** group, tagged so the operator
knows they came from you.

**Template placeholders** are filled from the GUI's input fields: common ones are `{target}`,
`{output}`, `{ports}`, `{iface}`, `{wordlist}`, `{user}`, `{password}`, `{domain}`, `{hash}`,
`{url}`, `{share}`, `{dc_ip}`. List each one you use in `--needs`. Always route scan/tool output
under `{output}` (e.g. `-oA {output}/<name>` for nmap).

## Rules you must follow (the tool enforces these; don't fight them)
- **Scope lock.** Only ever work against targets the operator confirms are in scope — RFC1918
  private addresses on the lab network. The console refuses public IPs, `169.254.169.254`, and
  anything outside the authorized CIDRs. Never suggest reaching the internet or anything off the
  lab network. If scope is unclear, stop and ask.
- **No destructive commands.** The `add_custom_action` safety screen refuses templates with
  DoS/flooding/wipe tokens (`dos`, `flood`, `hping3`, `rm -rf /`, fork bombs, `mkfs`, `dd`,
  `shutdown`, etc.). Don't try to work around it. This tool is for recon, enumeration,
  authenticated-access testing, offline cracking, passive capture, and in-lab pivoting only.
- **Manual-run, operator-owned.** You never execute attack commands yourself. The console shows
  every command in an editable field and the **operator** reviews and clicks Run. Your job is to
  propose and explain, not to fire.
- **Stay quiet.** Staying undetected by the blue team is a scored objective. Prefer `quiet`
  commands (slow timing, rate limits, null-session/passive enumeration, offline cracking) and
  **warn the operator before anything `loud`** (full/aggressive scans, password sprays, brute
  force, authenticated code execution). The GUI's "Stealth mode" hides `loud` commands by default.
- **Stay on-box.** Do not send the operator's recon data, tool output, or prompts off this VM.
  The console's AI client only talks to a localhost model endpoint by design.

## How the operator launches the tool
```
python3 app.py
```
Run from the Kali desktop session. Everything is stdlib-only (needs `python3-tk`, installed by
`setup.sh`). Output and your added commands live under `~/dogpark/`.

## Where things are
- `dogpark/tools.py` — the base command registry (data). `dogpark/catalog/*.py` — the deep
  per-group command sets. `dogpark/custom.py` — the runtime add-a-command API you use.
- `dogpark/scope.py` — the scope lock. `dogpark/llm.py` — the localhost-only AI client.
- `~/dogpark/custom_actions.json` — your added commands. `~/dogpark/runs|session|findings|loot`
  — the evidence trail.
