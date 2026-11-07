# DOGPARK — Phase 0 Deployment & Rebuild Tracking Doc

**Purpose:** The pentest will run on a **fresh Kali VM** (`m009073071-kali-pentest`, VM 455 on
Proxmox node `ncl1`). It comes up **bare**: same AI soul (Hermes running
**Nemotron-3.5-Lightning** via the CSUSB CyberLab API) but **none** of the tools, repos,
wordlists, configs, or the DOGPARK Console. This doc is the single checklist to rebuild
everything during **Phase 0 (Day 0), Sat/Sun, while internet is still available.**

> **Hard constraint (from the playbook + SOUL.md):** Internet access exists **only** in Phase 0.
> Once Day 1 begins, all external connectivity is permanently severed — no downloads, no external
> DNS, no cloud. **Download/clone/install everything now. There are no second chances.**
>
> Note the tension to respect: SOUL.md says *"No egress: do not download tools from the internet;
> use what is installed in the lab image."* The playbook says *"internet is available only during
> Phase 0 — download everything now."* **Reading we're using:** Phase 0 provisioning (apt/git) is
> the allowed one-time setup; after that the "no egress" rule is absolute. All *targets* stay
> RFC1918 the entire time.

---

## 0. One-command bootstrap (do this first on the new box)

```bash
# Phase 0, internet up, on the Kali desktop:
git clone https://github.com/xwiskas/dogpark-console.git
cd dogpark-console
bash setup.sh        # installs the FULL kit: apt tools + /opt/pentest-tools repos + wordlists
python3 app.py       # launch the console GUI
```

`setup.sh` is idempotent (safe to re-run) and prints any repo that failed to clone so you can
retry before the network drops.

---

## 1. Tool inventory — everything that must be on the box

### 1a. APT packages (installed by `setup.sh`)

| Tool | Purpose | Noise |
|------|---------|-------|
| nmap | Network scanning / host & service discovery | quiet at `-T2` |
| nikto | Web vulnerability scanner | loud |
| enum4linux / enum4linux-ng | SMB/AD null-session enumeration | quiet |
| gobuster / ffuf / feroxbuster | Directory & vhost brute-force / web fuzzing | normal |
| nuclei | Templated web/vuln scanning (DMZ) | normal–loud |
| hydra | Credential brute-force | loud |
| hashcat / john | GPU / CPU hash cracking (offline) | silent |
| smbclient / smbmap | SMB share access & mapping | quiet |
| crackmapexec / netexec | AD/SMB post-exploitation & spraying | normal |
| impacket-scripts / python3-impacket | secretsdump, psexec, GetNPUsers, etc. | normal |
| ldapdomaindump | LDAP directory dump | quiet |
| bloodhound.py | BloodHound collector over LDAP | quiet |
| responder | LLMNR/NBT-NS — **use `-A` (analyze/listen only)** | quiet in `-A`, loud poisoning |
| mitm6 | IPv6 DNS takeover | loud |
| wireshark / tcpdump / arpwatch / p0f | Passive capture, monitoring, OS fingerprinting | passive |
| netcat-openbsd / socat | Listeners, pivots, relays | quiet |
| metasploit-framework | Exploit framework | normal–loud |
| sqlmap | Automated SQL injection | loud |
| evil-winrm | WinRM shell access | normal |
| sqlitebrowser | DB inspection / cred extraction from DB files | silent |
| seclists | Wordlists (dirs, users, passwords) | — |
| dnsutils / dnsrecon | Internal DNS enumeration | quiet |
| arp-scan / netdiscover / fping / nbtscan | Quiet internal host discovery (find the blue team) | quiet |
| onesixtyone / snmp | SNMP enumeration (routers / perimeter) | quiet |
| ssh-audit | SSH config/version audit (perimeter) | quiet |
| exploitdb (searchsploit) | **Offline Exploit-DB** — find exploits with no internet | silent |
| proxychains4 / chisel | Run tools through a foothold / tunneling | quiet |
| whatweb | Web fingerprinting (passive-ish) | quiet |
| eyewitness | Screenshot every web service for fast triage | normal |
| hashid | Identify hash type before cracking | silent |
| cewl | Build wordlist from target's own site | quiet |
| ldap-utils (ldapsearch) | Raw lightweight LDAP queries | quiet |
| sslscan | TLS/SSL cipher & cert audit (perimeter, Phase 1) | quiet |
| wfuzz | Web parameter/content fuzzing (Day 4 param discovery) | normal |
| freerdp2-x11 (xfreerdp) | RDP client — Windows login/cred-reuse (3b, 5c, Phase 3) | normal |
| dirb + wordlists | `/usr/share/wordlists/dirb/common.txt`, rockyou symlink | — |
| macchanger | MAC spoofing (Appendix J evasion) | quiet |
| dsniff (arpspoof) | ARP tooling (Appendix H) — MITM, use with care | **loud** |
| python3-pip / curl / wget / unzip | Base utilities for the provisioner & binary pulls | — |

### 1b. pipx tools (modern AD tooling, installed by `setup.sh`)

| Tool | Purpose | Noise |
|------|---------|-------|
| certipy-ad | ADCS certificate abuse (ESC1–ESC16) — often cleanest path to DA | quiet |
| bloodyAD | Targeted AD object edits | quiet |
| coercer | Auth coercion for NTLM relay / ESC8 | **loud** |
| ldeep | Deep LDAP enumeration | quiet |
| pywerview | PowerView-style enum in python | quiet |
| adidnsdump | AD-integrated DNS zone dump | quiet |
| bloodhound-ce | BloodHound CE collector | quiet |
| name-that-hash | Hash identification | silent |

### 1c. Git repos → `/opt/pentest-tools/` (cloned by `setup.sh`, NOT in apt)

| Repo | Purpose | Noise |
|------|---------|-------|
| BloodHoundAD/BloodHound | AD attack-path mapping (classic) | quiet |
| carlospolop/PEASS-ng | LinPEAS / WinPEAS privilege-escalation | silent |
| PowerShellMafia/PowerSploit | PowerShell attack scripts | normal |
| gentilkiwi/mimikatz | Windows credential dumping | normal |
| BC-SECURITY/Empire | C2 framework | normal |
| Veil-Framework/Veil | Payload generation | silent |
| DominicBreuker/pspy | Process monitoring without root | silent |
| rebootuser/LinEnum | Linux enumeration script | silent |
| threat9/routersploit | Router / embedded-device exploitation | normal |
| ropnop/kerbrute | Kerberos user enum / password spray | quiet (spray slow) |
| nicocha30/ligolo-ng | Stealthy pivoting / tunneling | quiet |
| SnaffCon/Snaffler | SMB share credential hunting | quiet |
| lgandx/PCredz | Credentials from pcap | passive |
| topotam/PetitPotam | Coercion for ESC8 | **loud** |
| ropnop/windapsearch | LDAP enumeration | quiet |
| g0h4n/RustHound-CE | Fast BloodHound CE collector | quiet |
| BishopFox/sliver | Modern OPSEC C2 (build on box) | normal |
| HackTricks-wiki/hacktricks | **Offline methodology bible** | reference |
| swisskyrepo/PayloadsAllTheThings | Offline payloads + cheat sheets | reference |
| GTFOBins/GTFOBins.github.io | Linux lolbin priv-esc reference | reference |
| LOLBAS-Project/LOLBAS | Windows lolbin reference | reference |
| Flangvik/SharpCollection | Precompiled .NET (Rubeus/Seatbelt/Certify/SharpHound) | normal |
| diego-treitos/linux-smart-enumeration | Linux priv-esc enumeration | silent |
| 61106960/adPEAS | One-shot AD enumeration | quiet |

### 1d. Precompiled binaries → `/opt/pentest-tools/bin/` (fetched by `setup.sh`)

The playbook runs these **by name** (`./pspy64`, `./linpeas.sh`, `.\winPEAS.exe`, `mimikatz.exe`).
Source clones above do **not** yield a runnable artifact, so `setup.sh` pulls the release builds
during Phase 0. **If any land in the `FAILED` list, grab them manually before the network drops.**

| Binary | Purpose | Noise |
|--------|---------|-------|
| pspy64 / pspy32 | Process snooping without root (Linux) | silent |
| linpeas.sh | LinPEAS priv-esc, ready-to-run | silent |
| winPEASx64.exe | WinPEAS priv-esc (Windows) | silent |
| mimikatz_trunk/ | mimikatz `.exe` set (unzipped from release) | normal |

> SharpHound.exe, Rubeus, Seatbelt, Certify come precompiled in **SharpCollection** (§1c).

### 1e. The DOGPARK Console itself

The repo (`dogpark-console`) **is** a tool — 219 scope-locked, stealth-aware commands with a
GUI, an AI recon-chat panel, evidence logging, and a report generator. It is stdlib-only
(needs `python3-tk`, installed by `setup.sh`). Runs fully offline after Phase 0.

---

## 2. AI / LLM wiring (the "soul")

The on-box agent is **Hermes → Nemotron-3.5-Lightning**, reached via the **CSUSB CyberLab API**.
The DOGPARK Console's AI panel (`dogpark/llm.py`) is **localhost-only by design** — it will only
talk to `127.0.0.1` (Ollama `11434` / Hermes `8642`), so recon data never leaves the box.

**Saturday check:** find the local endpoint and wire it into `config.json`:

```bash
ss -ltnp | grep -E '11434|8642|20128'   # is a model listening locally?
```

- If a local model answers → set it in `config.json` `"llm".endpoints/model`; the console's
  **Explain / What-next / Chat** become live.
- If Nemotron is **only** reachable off-box via the CyberLab API → **leave the console on canned
  guidance.** That's the safe/stealthy default (no recon data leaves the VM). The canned recon
  plan still works offline.

---

## 3. DOGPARK rulebook (playbook + SOUL.md essentials)

### Timeline — Pre-Engagement + 7 Operational Days
- **Day 0:** Pre-Engagement (this doc — tool install, scope confirm)
- **Days 1–2:** Subscreen phase (perimeter devices — OPNSense/Vyatta, default-cred testing)
- **Days 3–5:** DMZ phase (web app attacks, e.g. Juice Shop)
- **Days 6–7:** LAN phase (internal pivot, AD enumeration, privilege escalation)

### Scope lock (non-negotiable — enforced in the console)
- All targets within RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`.
- **No** public IPs, cloud-metadata (`169.254.169.254`), or globally routable ranges.
- CIDR blocks spilling outside permitted ranges are out of scope.
- Verify every target IP against the allowlist before acting. **If scope is unclear → stop & ask.**

### Primary goal
- **Day 7:** Domain Administrator compromise — full LAN pivot, data exfil (in-lab), persistent
  domain access (Golden Ticket is in the rulebook as a documented objective).

### Stealth principle (scored)
- Staying undetected by the blue team is scored. Prefer quiet risk levels: slow timing, minimal
  parallelism, skip DNS (`-n`), skip host discovery (`-Pn`), avoid aggressive timing (`-T4/-T5`).
  The console's **Stealth mode** (on by default) hides every `loud` command.

### No destructive commands
- No `rm -rf /`, `dd`, `mkfs`, DoS/flooding. Recon, enumeration, authenticated-access testing,
  offline cracking, passive capture, in-lab pivoting only. (Enforced by the console's safety screen.)

---

## 4. Lab environment (from session context — confirm live on the day)

| Role | Address (from images; re-confirm) |
|------|-----------------------------------|
| Attack platform (Kali) | 192.168.1.100 |
| "Blue team" target (Metasploitable2) | 192.168.1.194 |
| Additional target (OWASP Juice Shop) | 192.168.1.182:3000 |
| Lab network | RFC1918 — 192.168.1.x |

Machines to inventory during the engagement (Appendix N): **Windows Client, RHEL Client,
LAN Router, Domain Controller** — each `[YES/NO] | Access: ___`.

---

## 5. Command quick-reference (from your Obsidian notes + Hermes)

The console has all of these as click-to-run buttons; this is the cheat sheet.

**Recon (quiet-first):**
```
nmap -sn 192.168.1.0/24                    # ping sweep, find live hosts
nmap -sS -T2 -n -Pn --top-ports 100 <ip>   # quiet SYN scan, no DNS, no host-discovery
nmap -sV -O <ip>                           # service/version + OS (louder)
nmap --script "vuln and safe" <ip>         # safe vuln scripts
```

**SMB / AD enumeration:**
```
enum4linux -a <ip>                         # null-session enum
smbclient -L //<ip> -N                     # list shares, null session
crackmapexec smb <subnet>                  # sweep / spray across LAN
python3 secretsdump.py <domain>/<user>@<dc_ip> --just-dc   # DCSync dump
evil-winrm -i <ip> -u <user> -p <pass>     # WinRM shell
```

**Password cracking:**
```
hashcat -m 13100 <hashes> rockyou.txt      # Kerberoast (TGS-REP)
hashcat -m 18200 <hashes> rockyou.txt      # AS-REP roast
john --wordlist=/usr/share/wordlists/rockyou.txt <hashes>
```

**Web / DB:**
```
nikto -h http://<ip>
gobuster dir -u http://<ip> -w /usr/share/seclists/Discovery/Web-Content/common.txt
ffuf -u http://<ip>/FUZZ -w <wordlist>
sqlmap -u "http://<ip>/page?id=1" --batch --dbs
```

**Priv-esc (post-access):**
```
/opt/pentest-tools/PEASS-ng/linPEAS/linpeas.sh     # Linux
# winPEAS.exe on Windows; pspy for process monitoring without root
```

---

## 6. Saturday / Sunday checklist

- [ ] New VM booted, internet confirmed (`ping -c1 1.1.1.1` — Phase 0 only)
- [ ] `git clone` the dogpark-console repo
- [ ] `bash setup.sh` — confirm **0 failed repos** at the end (retry any while still online)
- [ ] `rockyou.txt` unzipped; `/usr/share/seclists` present
- [ ] `/opt/pentest-tools/` has all repos (25); `/opt/pentest-tools/bin/` has pspy64, linpeas.sh, winPEASx64.exe, mimikatz_trunk/
- [ ] `ss -ltnp | grep -E '11434|8642|20128'` — decide live-model vs canned (§2)
- [ ] Confirm lab subnet / target IPs; set `config.json` `lab_subnet` + `inventory`
- [ ] Launch `python3 app.py` — scope badge works, AGENTS.md readable by on-box AI
- [ ] (Optional) `script -a ~/dogpark/session/day0_terminal.log` to start the evidence trail
- [ ] **Before Day 1 ends:** verify everything is local — nothing left to download

---

## 7. What's in the repo vs. this doc
- **Repo (travels via `git pull`):** `setup.sh`, `app.py`, `dogpark/` (219 commands, scope lock,
  stealth, custom-command store, llm), `AGENTS.md`, `README.md`, `config.json`, `tests/`.
- **This doc:** the rebuild checklist, the full tool inventory (incl. the extra apt + git repos),
  the rulebook summary, and the command cheat sheet — so the bare box becomes the full kit in one pass.
