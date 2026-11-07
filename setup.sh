#!/usr/bin/env bash
# DOGPARK Console — Phase 0 complete provisioner.
# Run this ONCE, on the fresh Kali box, WHILE INTERNET ACCESS IS STILL AVAILABLE.
# Internet is cut after Day 1 per the playbook — if you skip this now, you're stuck offline.
#
# Safe to re-run: every step is idempotent (apt skips installed pkgs, pipx/git skip existing).
# If something fails it keeps going and lists all failures at the end so you can retry online.
set -uo pipefail

echo "=== DOGPARK Console: Phase 0 complete provisioner ==="
echo "Installs the full lab kit: apt tools + pipx tools + /opt/pentest-tools repos + wordlists."
echo "Run this NOW while you're online — it will not work once the lab goes offline."
echo
FAILED=()

# ===========================================================================
# 1. APT packages
# ===========================================================================
echo "=== [1/5] apt packages ==="
sudo apt update
sudo apt install -y \
    python3 python3-tk python3-venv pipx git \
    `# --- console core / lab kit ---` \
    nmap nikto enum4linux gobuster ffuf hydra hashcat john \
    smbclient smbmap crackmapexec netexec impacket-scripts python3-impacket \
    wireshark tcpdump arpwatch netcat-openbsd socat \
    metasploit-framework sqlmap evil-winrm sqlitebrowser seclists dnsutils \
    `# --- stealthy AD / enumeration ---` \
    enum4linux-ng ldapdomaindump bloodhound.py responder mitm6 \
    `# --- web / DMZ ---` \
    feroxbuster nuclei \
    `# --- recon / discovery (quiet, internal) ---` \
    arp-scan netdiscover fping nbtscan onesixtyone snmp snmp-mibs-downloader \
    dnsrecon p0f ssh-audit \
    `# --- offline exploit DB, pivoting, web triage, hash/wordlist ---` \
    exploitdb proxychains4 chisel whatweb eyewitness hashid cewl ldap-utils \
    `# --- playbook v3.0 explicit tools (Phase 1 / Appendices A-J) ---` \
    sslscan wfuzz dirb wordlists macchanger dsniff \
    python3-pip curl wget unzip \
    || FAILED+=("one or more apt packages (see apt output above)")

# RDP client: the playbook calls `xfreerdp` (freerdp2). Kali rolling may ship freerdp3
# instead, so try the v2 package first and fall back without aborting the whole run.
echo "  [rdp] installing an xfreerdp client ..."
if ! command -v xfreerdp >/dev/null 2>&1; then
    sudo apt install -y freerdp2-x11 2>/dev/null \
        || sudo apt install -y freerdp3-x11 2>/dev/null \
        || FAILED+=("freerdp (xfreerdp RDP client — install manually)")
fi

# ===========================================================================
# 2. pipx tools (modern Python AD tooling not always in apt)
# ===========================================================================
echo
echo "=== [2/5] pipx tools ==="
pipx ensurepath >/dev/null 2>&1 || true
pipx_install() {  # pipx_install <package> <friendly-name>
    if pipx list 2>/dev/null | grep -qi "package $1 "; then
        echo "  [skip] $2 already installed"; return
    fi
    echo "  [pipx] $2"
    pipx install "$1" >/dev/null 2>&1 || FAILED+=("pipx:$1")
}
pipx_install certipy-ad     "Certipy (ADCS ESC abuse)"
pipx_install bloodyAD       "bloodyAD (AD object edits)"
pipx_install coercer        "Coercer (auth coercion)"
pipx_install ldeep          "ldeep (deep LDAP enum)"
pipx_install pywerview      "pywerview (PowerView-in-python)"
pipx_install adidnsdump     "adidnsdump (AD-integrated DNS dump)"
pipx_install bloodhound-ce  "BloodHound CE python collector"
pipx_install name-that-hash "name-that-hash (hash identification)"

# ===========================================================================
# 3. GitHub repos -> /opt/pentest-tools/  (not in apt; grab now)
# ===========================================================================
echo
echo "=== [3/5] git repos -> /opt/pentest-tools/ ==="
sudo mkdir -p /opt/pentest-tools
sudo chown "$USER" /opt/pentest-tools
clone() {  # clone <url> <dir> <description>
    if [ -d "/opt/pentest-tools/$2/.git" ]; then echo "  [skip] $2 already cloned"; return; fi
    echo "  [clone] $2 — $3"
    git clone --depth 1 "$1" "/opt/pentest-tools/$2" >/dev/null 2>&1 || FAILED+=("git:$2 ($1)")
}
# --- original lab kit ---
clone https://github.com/BloodHoundAD/BloodHound.git      BloodHound   "AD attack-path mapping (classic)"
clone https://github.com/carlospolop/PEASS-ng.git         PEASS-ng     "LinPEAS / WinPEAS priv-esc"
clone https://github.com/PowerShellMafia/PowerSploit.git  PowerSploit  "PowerShell attack scripts"
clone https://github.com/gentilkiwi/mimikatz.git          mimikatz     "Windows credential dumping"
clone https://github.com/BC-SECURITY/Empire.git           Empire       "C2 framework"
clone https://github.com/Veil-Framework/Veil.git          Veil         "payload generation"
clone https://github.com/DominicBreuker/pspy.git          pspy         "process monitoring (no root)"
clone https://github.com/rebootuser/LinEnum.git           LinEnum      "Linux enumeration"
clone https://github.com/threat9/routersploit.git         routersploit "router/embedded exploitation"
# --- stealthy AD / recon additions ---
clone https://github.com/ropnop/kerbrute.git              kerbrute     "Kerberos user enum / spray (quiet)"
clone https://github.com/nicocha30/ligolo-ng.git          ligolo-ng    "stealthy pivoting/tunneling"
clone https://github.com/SnaffCon/Snaffler.git            Snaffler     "SMB share credential hunting"
clone https://github.com/lgandx/PCredz.git                PCredz       "creds from pcap (passive)"
clone https://github.com/topotam/PetitPotam.git           PetitPotam   "coercion for ESC8 (LOUD)"
clone https://github.com/ropnop/windapsearch.git          windapsearch "LDAP enum (quiet)"
clone https://github.com/g0h4n/RustHound-CE.git           RustHound-CE "BloodHound CE collector (fast)"
clone https://github.com/BishopFox/sliver.git             sliver       "modern OPSEC C2 (build on box)"
# --- offline reference material (CRITICAL: no internet after Day 1) ---
clone https://github.com/HackTricks-wiki/hacktricks.git             hacktricks           "offline pentest methodology bible"
clone https://github.com/swisskyrepo/PayloadsAllTheThings.git       PayloadsAllTheThings "offline payloads + cheat sheets"
clone https://github.com/GTFOBins/GTFOBins.github.io.git            GTFOBins             "Linux lolbin priv-esc reference"
clone https://github.com/LOLBAS-Project/LOLBAS.git                  LOLBAS               "Windows lolbin reference"
# --- precompiled .NET + more priv-esc ---
clone https://github.com/Flangvik/SharpCollection.git               SharpCollection      "precompiled .NET (Rubeus/Seatbelt/Certify/SharpHound)"
clone https://github.com/diego-treitos/linux-smart-enumeration.git  lse                  "Linux priv-esc enumeration"
clone https://github.com/61106960/adPEAS.git                        adPEAS               "one-shot AD enumeration"

# ===========================================================================
# 3.5 Precompiled binaries / release artifacts
#     The playbook runs these BY NAME (./pspy64, ./linpeas.sh, .\winPEAS.exe,
#     mimikatz.exe). Source clones above do NOT give you a runnable binary, so
#     grab the release builds now — there is no internet after Day 1.
#     (SharpHound.exe, Rubeus, Seatbelt, Certify come from SharpCollection above.)
# ===========================================================================
echo
echo "=== [3.5/5] precompiled binaries -> /opt/pentest-tools/bin ==="
BINDIR=/opt/pentest-tools/bin
sudo mkdir -p "$BINDIR"; sudo chown "$USER" "$BINDIR"
fetch() {  # fetch <url> <outfile> <description>
    if [ -s "$BINDIR/$2" ]; then echo "  [skip] $2 already present"; return; fi
    echo "  [get]  $2 — $3"
    if curl -fsSL "$1" -o "$BINDIR/$2" 2>/dev/null || wget -q "$1" -O "$BINDIR/$2" 2>/dev/null; then
        chmod +x "$BINDIR/$2" 2>/dev/null || true
    else
        rm -f "$BINDIR/$2"; FAILED+=("binary:$2 ($1)")
    fi
}
fetch https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 pspy64 "process snooping, no root (Linux x64)"
fetch https://github.com/DominicBreuker/pspy/releases/latest/download/pspy32 pspy32 "pspy (Linux x86)"
fetch https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh   linpeas.sh      "LinPEAS priv-esc (ready-to-run)"
fetch https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe winPEASx64.exe "WinPEAS priv-esc (Windows x64)"
# mimikatz ships its .exe set only as a release zip:
if [ -d "$BINDIR/mimikatz_trunk" ]; then
    echo "  [skip] mimikatz already extracted"
elif curl -fsSL https://github.com/gentilkiwi/mimikatz/releases/latest/download/mimikatz_trunk.zip -o "$BINDIR/mimikatz_trunk.zip" 2>/dev/null; then
    echo "  [get]  mimikatz_trunk.zip — Windows credential dumping (binaries)"
    unzip -oq "$BINDIR/mimikatz_trunk.zip" -d "$BINDIR/mimikatz_trunk" 2>/dev/null && rm -f "$BINDIR/mimikatz_trunk.zip" \
        || FAILED+=("mimikatz unzip (extract $BINDIR/mimikatz_trunk.zip manually)")
else
    FAILED+=("binary:mimikatz_trunk.zip")
fi

# ===========================================================================
# 4. Wordlists
# ===========================================================================
echo
echo "=== [4/5] wordlists ==="
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "  Unzipping rockyou.txt.gz ..."; sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
else
    echo "  rockyou.txt already present or not found — check /usr/share/wordlists/ manually."
fi
[ -d /usr/share/seclists ] && echo "  SecLists present at /usr/share/seclists" \
    || echo "  SecLists not found — 'sudo apt install seclists' while still online."

# ===========================================================================
# 5. Output directories for the evidence trail
# ===========================================================================
echo
echo "=== [5/5] output directories ==="
# Playbook v3.0 workspace tree (so its copy-paste commands land) + console dirs.
mkdir -p ~/dogpark/{recon,exploits,loot,reports,screenshots,sessions,runs,findings,notes}
echo "  Created ~/dogpark/{recon,exploits,loot,reports,screenshots,sessions,runs,findings,notes}"

echo
echo "=== Done ==="
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "!! The following FAILED — retry them while you still have internet:"
    for f in "${FAILED[@]}"; do echo "   - $f"; done
    echo "   (kerbrute/ligolo-ng/sliver are source clones — build per their README.)"
else
    echo "Everything installed/cloned OK."
fi
echo
echo "Tools:   apt kit on PATH | source repos in /opt/pentest-tools/ | binaries in /opt/pentest-tools/bin/"
echo "Verify:  nmap --version; crackmapexec --version; sqlmap --version; evil-winrm --version; xfreerdp --version"
echo "         ls /opt/pentest-tools/bin/ (pspy64, linpeas.sh, winPEASx64.exe, mimikatz_trunk/)"
echo "REMINDER: run this during Phase 0 while the lab still has internet. After Day 1 it's cut."
