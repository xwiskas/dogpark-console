# DOGPARK Console — Build Spec

Offline **Tkinter** desktop app that helps a CSUSB student during **Operation DOGPARK**, an
authorized, isolated university cyberlab red-team exercise. It is a guided front-end over the
pentest tools already installed on the Kali box. It does **not** invent new attack capability —
it organizes the standard Kali tools, explains them, builds the exact command for a chosen
action, and **only runs it when the user clicks Run**. The pentester is responsible for every
command, per the playbook.

This tool is scoped-locked to the lab and is for a sanctioned class engagement only.

## Hard constraints (from the DOGPARK playbook — enforce these)
1. **Scope lock.** Every target is validated against an authorized-CIDR allowlist *before* a
   command can be built or run. Default allowlist = RFC1918 + loopback only
   (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, plus v6 `fc00::/7`,
   `fe80::/10`, `::1/128`) and a configurable lab subnet (default `192.168.1.0/24`).
   Public IPs, `169.254.169.254` (cloud metadata), and anything outside the allowlist are
   **refused** — the Run button disables and the UI shows why. If a hostname won't resolve to an
   in-scope IP, treat scope as unclear and stop.
2. **No egress / offline.** The app itself makes **no outbound internet calls** — no telemetry,
   no update checks, no fetching. The only network it touches: (a) the local LLM endpoint on the
   Kali box, (b) commands the user explicitly runs against in-scope lab targets. Everything works
   with the network cable effectively cut.
3. **Manual-first.** Never auto-run anything. Always display the exact, final command string in an
   **editable** field; the user reviews/edits, then clicks Run. AI suggestions are clearly labeled
   "AI-suggested — verify before running".
4. **Evidence-first.** Every run is timestamped, saved to the output dir, and appended to the
   day's session log. Encourage/support `script` logging, `-oA`/`tee`, password redaction,
   screenshots, and time-to-compromise tracking.

## Target platform
- Runs on Kali Linux (Debian) with system Python 3 (3.11+) and **stdlib only** — Tkinter, no pip
  installs required at runtime. (Dev machine is Windows/Py3.14; keep it cross-platform so it
  imports and unit-tests on Windows too, even though the tools only exist on Kali.)
- Delivered as a GitHub repo; cloned onto the Kali box during Phase 0 while internet is available.

## Modules (package `dogpark/`)
Create a small package plus an entry script `dogpark-console` / `app.py`.

### `dogpark/scope.py`
- `Scope` class loaded from config: list of allowed CIDRs (ipaddress networks), plus an optional
  explicit target inventory.
- `check(target) -> ScopeResult(ok: bool, ip, reason)`: resolve hostname→IP using the stdlib
  (`socket.getaddrinfo`); validate the IP is in an allowed network and not a public/metadata/
  link-local-APIPA address. Reject `169.254.0.0/16` even though it's "private-ish".
- Pure, unit-testable, no GUI imports. Ship `tests/test_scope.py` covering: in-range allow,
  public reject (e.g. 8.8.8.8), metadata reject, out-of-subnet reject, bad hostname → not ok.

### `dogpark/tools.py`
- A static registry: list of `Tool(name, binary, phases, category, summary, when_to_use, actions)`.
- Each `Action(id, label, phase, description, risk, template, needs)` where `template` is a
  command string with named placeholders like `{target} {ports} {wordlist} {iface} {output} {userlist} {url}`,
  and `needs` lists which inputs it requires. Include a plain-English `description` of what the
  action does and `risk`/noise level (quiet | normal | loud) so the UI can show a "stealth"
  vs "loud" variant where it applies (e.g. nmap `-T2 -sS` quiet vs `-T4 -A` loud; a `--max-rate`
  option). Do NOT include anything destructive/DoS — no flooding, no `--script dos`, no mass-nuke.
- Cover the installed toolset, each with a handful of graded actions (recon→enum→exploit-assist):
  - **Host discovery / "find the blue team"**: `nmap -sn` sweep of the in-scope subnet, `arp-scan`
    alternative via `nmap --script broadcast` / `ip neigh`, netdiscover-style passive note.
  - **nmap** (port/service/version/scripts, quiet and full variants, `-oA` output).
  - **nikto** (web server scan).
  - **gobuster / ffuf** (dir & vhost brute with a wordlist placeholder; default
    `/usr/share/wordlists/...`).
  - **enum4linux**, **smbclient**, **smbmap**, **crackmapexec** (SMB/AD enumeration; auth'd and
    null-session variants).
  - **impacket-scripts** (e.g. `GetUserSPNs`, `secretsdump`, `psexec` — enumeration/auth with
    supplied creds; label clearly, require creds).
  - **hydra** (service login testing with user+wordlist placeholders; include a "respect lockout"
    note and conservative rate default).
  - **john / hashcat** (offline hash cracking with a hashfile + wordlist placeholder).
  - **tcpdump / wireshark / arpwatch** (passive capture to a file).
  - **netcat / socat** (listener / connect / file transfer between in-scope hosts — for pivoting
    and loot movement inside the lab).
- All templates must route output under the configured output dir and use safe quoting.

### `dogpark/runner.py`
- `run(command, cwd, env, on_line)` using `subprocess.Popen`, line-streaming stdout+stderr to a
  callback so the GUI can show live output. Non-blocking (thread). Support cancel/terminate.
- Writes a timestamped `.log` per run under `<output>/runs/` and appends a one-line record
  (timestamp, target, action id, command, exit code, log path) to `<output>/session/dayN.jsonl`.
- Never shells out to anything the user didn't click. On Windows (dev) just echo that the tool is
  Kali-only but still exercise the save/log path with a harmless command.

### `dogpark/evidence.py`
- Helpers: start-of-day `script -a` command builder, finding notes store
  (`<output>/findings.jsonl`: id, time, target, severity, title, evidence_path, impact,
  remediation), time-to-compromise tracker per machine, a `redact(text)` that masks obvious
  passwords/hashes, and a screenshot reminder hook.

### `dogpark/report.py`
- Generate the **Appendix N** report from the session logs + findings store into a single
  Markdown file (and a plain `.txt`): Executive Summary, Scope & Methodology, Attack Narrative
  (chronological from session logs), Findings Table (Critical/High/Medium/Low/Info counts),
  Detailed Findings (evidence+impact+remediation), Attack Path (initial access → Domain Admin),
  Remediation Priority Matrix, Appendices (list of raw scan logs). Also emit
  `phase1_subscreen_summary.txt`, `phase2_dmz_summary.txt`, `phase3_lan_summary.txt` stubs and an
  engagement-doc header (Domain, DC IP, Domain Admin Y/N + method, machine inventory, creds
  harvested, time-to-DA). Keep passwords redacted in the report.

### `dogpark/llm.py`
- Offline local-model client. Endpoint auto-detect in this order, all localhost:
  1. Ollama OpenAI-compat `http://127.0.0.1:11434/v1/chat/completions` (and native
     `/api/chat`), model from config (default `nemotron-3.5-lightning` then fall back to any
     available), 2. a Hermes/OmniRoute style `http://127.0.0.1:8642/v1/...` if present.
- Two calls: `explain(output_text, context)` → plain-English read of a tool's output, and
  `suggest_next(state)` → next-step ideas **as text only**, always prefixed with
  "AI-suggested — verify before running" and constrained to in-scope targets and the current
  phase. Short timeouts; if unreachable, return built-in canned guidance. Never block the GUI.
- Uses only `urllib` (stdlib). No API keys, no external hosts.

### `dogpark/app.py` (Tkinter GUI)
- Top bar: **Target** entry + **live scope badge** (green "IN SCOPE 192.168.1.x" / red "REFUSED:
  reason"), **Phase** selector (0 Pre-engagement / 1-2 Subscreen / 3-5 DMZ / 6-7 LAN),
  output-dir label, and a Day counter that drives the session log name.
- Left: tree of tools filtered by the selected phase + a "Host discovery" group at top.
- Center: selected action's description/risk, the input fields it needs (wordlist, ports, creds,
  iface…), and the **editable command preview**. Buttons: **Run**, **Stop**, **Explain output**,
  **What next?**, **Add finding**, **Generate report**. Run is disabled unless scope badge is green.
- Bottom: live output console (monospace), with Save-copy.
- Everything keyboard-reachable; no modal surprises.

### `config.json`
```
{
  "allowed_cidrs": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"],
  "lab_subnet": "192.168.1.0/24",
  "output_dir": "~/dogpark",
  "wordlists": {"dirb":"/usr/share/wordlists/dirb/common.txt","rockyou":"/usr/share/wordlists/rockyou.txt"},
  "llm": {"endpoints": ["http://127.0.0.1:11434","http://127.0.0.1:8642"], "model": "nemotron-3.5-lightning"},
  "inventory": {"windows_client":"","rhel_client":"","lan_router":"","domain_controller":""}
}
```

### `setup.sh` (Phase 0, run on Kali while online)
- `sudo apt update && sudo apt install -y nmap nikto enum4linux gobuster ffuf hydra hashcat john
  smbclient smbmap crackmapexec impacket-scripts wireshark tcpdump arpwatch netcat-openbsd socat`
- Note to unzip `/usr/share/wordlists/rockyou.txt.gz`, create `~/dogpark/{runs,session,findings,loot}`.
- Print a reminder that this must happen in Phase 0 (internet is cut after Day 1).

### `README.md`
- One-screen: what it is (authorized CSUSB DOGPARK lab helper), the manual-verify / scope-lock /
  no-egress principles, Phase 0 clone+setup steps, how to launch (`python3 app.py`), and the
  evidence/report workflow. Include the "you are responsible for every command" notice.

## Quality bar
- `python3 app.py` launches on Kali with stdlib only; imports cleanly on Windows dev too.
- `python -m pytest tests/` passes (scope + report + template-render unit tests; no live tools).
- No network calls at import/startup. No auto-run. Scope rejection provably blocks Run.
- Clean, readable, commented where non-obvious. Keep it a tight, single-purpose codebase.
