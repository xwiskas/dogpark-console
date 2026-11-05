# DOGPARK Console

An offline, Tkinter desktop helper for Cal State San Bernardino's **Operation DOGPARK**
cyberlab red-team class exercise. This is a sanctioned, isolated class engagement — the
console is a guided front-end over the standard Kali pentest tools already installed on the
student's VM. It does not add new attack capability: it organizes the tools, explains what
each action does, builds the exact command for the chosen action, and only runs it when the
user clicks **Run**.

**You are responsible for every command this tool builds.** The console shows the command
in an editable field before anything runs; review it, edit it if needed, then run it
yourself. Nothing here auto-executes.

## Principles (non-negotiable, enforced in code)

- **Scope lock.** Every target is checked against an authorized-CIDR allowlist (RFC1918 +
  loopback + the configured lab subnet) before a command can be built or run. Public IPs,
  the `169.254.169.254` cloud-metadata address, and anything that doesn't resolve to an
  in-scope IP are refused — the Run button stays disabled and the scope badge shows why.
- **No egress / offline.** The app itself makes no outbound internet calls — no telemetry,
  no update checks, no background fetching. The only network it touches is (a) a local LLM
  endpoint on the Kali box (`127.0.0.1` only) for optional "Explain output" / "What next?"
  help, and (b) whatever command you explicitly run against an in-scope lab target.
- **Manual-first.** The console never auto-runs anything. It always shows the final command
  string in an editable field. AI suggestions are always labeled "AI-suggested — verify
  before running".
- **Evidence-first.** Every run is timestamped, logged to `<output>/runs/`, and appended to
  the day's session log (`<output>/session/dayN.jsonl`). Findings, time-to-compromise, and
  the final Appendix N report all build from that trail.

## Phase 0 — set up while you still have internet

Internet access is cut after Day 1. Do this now:

```bash
git clone <this-repo-url> dogpark-console
cd dogpark-console
chmod +x setup.sh
./setup.sh
```

`setup.sh` installs the Kali tools the console drives (nmap, nikto, gobuster, ffuf, hydra,
hashcat, john, smbclient, smbmap, crackmapexec, impacket-scripts, wireshark, tcpdump,
arpwatch, netcat, socat), unzips `rockyou.txt.gz` if present, and creates
`~/dogpark/{runs,session,findings,loot,report}`.

## Launching

```bash
python3 app.py
```

No pip installs are required — the app is stdlib-only (Tkinter, urllib, subprocess,
ipaddress, socket, json, threading). It also imports and unit-tests cleanly on a Windows dev
box, though the actual Kali tools only exist on the Kali VM — on Windows, Run exercises the
save/log path with a harmless stub instead of a real command.

## Using it

1. Enter a **Target** — the scope badge goes green ("IN SCOPE ...") or red ("REFUSED:
   ...") immediately.
2. Pick a **Phase** (0 Pre-engagement / 1-2 Subscreen / 3-5 DMZ / 6-7 LAN) to filter the tool
   tree on the left. Host discovery is always pinned at the top.
3. Select an action. Fill in whatever inputs it needs (ports, wordlist, creds, interface...).
   Watch the **command preview** build live — it's a normal editable text field, so fix
   anything before running.
4. Click **Run** (disabled unless scope is green). Watch live output in the console at the
   bottom. **Stop** terminates the running process.
5. **Explain output** asks the local LLM (if reachable) for a plain-English read of the
   console output; falls back to canned guidance if no local model answers.
6. **What next?** asks for AI-suggested next steps, always prefixed "AI-suggested — verify
   before running" and scoped to the current phase/target.
7. **Add finding** records a finding (severity, evidence path, impact, remediation) to
   `<output>/findings.jsonl`.
8. **Generate report** builds the Appendix N Markdown/plain-text report plus phase summary
   stubs from the session logs and findings store.

## Evidence & reporting workflow

- Start each day with a terminal transcript: the command `evidence.script_command(...)`
  builds (`script -a <output>/session/dayN_terminal.log`) runs alongside the console's own
  per-action logs.
- Every run writes a timestamped `.log` under `<output>/runs/` and a one-line JSON record
  to `<output>/session/dayN.jsonl` (timestamp, target, action id, command, exit code, log
  path).
- `redact()` masks obvious passwords/hashes before anything goes into a screenshot or the
  report — still double-check before sharing.
- `Generate report` produces `<output>/report/appendix_n_report.{md,txt}` (Executive
  Summary, Scope & Methodology, Attack Narrative, Findings Table, Detailed Findings, Attack
  Path, Remediation Priority Matrix, Appendices) plus `phase1_subscreen_summary.txt`,
  `phase2_dmz_summary.txt`, and `phase3_lan_summary.txt`.

## Configuration

See `config.json` for the allowlist, lab subnet, output dir, wordlist paths, local LLM
endpoints/model, and the machine-inventory fields used in the report header.

## Tests

```bash
python -m pytest tests/ -q
```

Covers scope checks (in-range allow, public reject, metadata reject, out-of-subnet reject,
bad-hostname reject) and report/template rendering — no live tools required, and nothing
here touches the network.
