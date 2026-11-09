#!/usr/bin/env bash
# DOGPARK — Offline-readiness pass. Run ONCE on the Kali box WHILE INTERNET IS STILL UP (Phase 0).
# Fills the gaps setup.sh didn't, grabs the internet-only bits (nuclei templates!), then verifies.
# Idempotent and safe to re-run. Puts big stuff on /opt/extra (the 5 GB partition) to spare root.
#
#   cd ~/dogpark-console && git pull && bash offline_prep.sh
#
set -uo pipefail
FAILED=()
note(){ echo; echo "=== $* ==="; }
try(){ echo "[*] $*"; "$@" || FAILED+=("$*"); }

EXTRA=/opt/extra
[ -d "$EXTRA" ] || { echo "WARNING: $EXTRA not mounted — big items will land on root. Mount sda3 there first."; EXTRA=/opt/pentest-tools; }

note "[1/7] apt index (needed — lists were cleared earlier)"
sudo apt update || FAILED+=("apt update")

note "[2/7] core offline gaps (small, essential)"
sudo apt install -y \
  ldap-utils krb5-user \
  default-mysql-client postgresql-client redis-tools \
  proxychains4 faketime \
  nuclei feroxbuster whatweb sslscan dnsrecon \
  || FAILED+=("apt core gaps")
# ldapsearch(ldap-utils), kinit/klist(krb5-user), DB clients(DMZ .200), proxychains(pivot),
# faketime(Kerberos clock skew), nuclei/feroxbuster/whatweb/sslscan/dnsrecon(web/DMZ recon).
sudo apt install -y python3-ldapdomaindump || FAILED+=("python3-ldapdomaindump")

note "[3/7] nuclei templates (REQUIRED — nuclei is useless offline without them)"
try nuclei -update-templates

note "[4/7] offline exploit DB -> searchsploit"
if [ ! -d "$EXTRA/exploitdb" ]; then
  try git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$EXTRA/exploitdb"
fi
[ -f "$EXTRA/exploitdb/searchsploit" ] && sudo ln -sf "$EXTRA/exploitdb/searchsploit" /usr/local/bin/searchsploit

note "[5/7] reference repos -> $EXTRA (skip any already present)"
cd "$EXTRA" || exit 1
for url in \
  https://github.com/swisskyrepo/PayloadsAllTheThings.git \
  https://github.com/HackTricks-wiki/hacktricks.git \
  https://github.com/LOLBAS-Project/LOLBAS.git \
  https://github.com/diego-treitos/linux-smart-enumeration.git \
  https://github.com/61106960/adPEAS.git \
  https://github.com/t3l3machus/PsMapExec.git ; do
  n=$(basename "$url" .git)
  [ -d "$n" ] || try git clone --depth 1 "$url"
done
cd - >/dev/null

note "[6/7] OPTIONAL heavy — BloodHound GUI + neo4j (to ANALYZE AD paths, not just collect)"
echo "    ~1 GB + Java. Uncomment the next line if you have disk headroom (check 'df -h /' first)."
# sudo apt install -y bloodhound neo4j || FAILED+=("bloodhound/neo4j")

note "[7/7] workspace dirs"
mkdir -p ~/dogpark/{recon,exploits,loot,reports,screenshots,sessions,runs,findings,notes}

# ---------------------------------------------------------------------------
note "INVENTORY -> $EXTRA/TOOL_INVENTORY.txt"
{
  echo "# DOGPARK tool inventory — $(date)"
  echo; echo "## On PATH:"
  for t in nmap nxc crackmapexec evil-winrm responder impacket-secretsdump impacket-GetUserSPNs \
           certipy bloodhound-python ldapsearch kinit hashcat john hydra ffuf feroxbuster gobuster \
           nuclei nikto sqlmap msfconsole searchsploit proxychains4 mysql psql redis-cli xfreerdp faketime; do
    p=$(command -v "$t" 2>/dev/null) && echo "  OK   $t -> $p" || echo "  MISS $t"
  done
  echo; echo "## /opt/pentest-tools:"; ls /opt/pentest-tools 2>/dev/null
  echo; echo "## /opt/extra:"; ls "$EXTRA" 2>/dev/null
  echo; echo "## nuclei templates:"; ls -d ~/.local/nuclei-templates ~/nuclei-templates 2>/dev/null || echo "  (none found — re-run nuclei -update-templates)"
  echo; echo "## wordlists:"; ls -d /usr/share/wordlists/rockyou.txt /usr/share/seclists 2>/dev/null
  echo; echo "## workspace:"; ls ~/dogpark 2>/dev/null
} | tee "$EXTRA/TOOL_INVENTORY.txt"

# ---------------------------------------------------------------------------
note "VERIFY — must-haves for the engagement"
ok=0; miss=0
check(){ if command -v "$1" >/dev/null 2>&1 || [ -e "$2" ]; then echo "  OK   $3"; ok=$((ok+1)); else echo "  MISS $3  <-- $4"; miss=$((miss+1)); fi; }
check nmap "" "nmap (scanning)" "sudo apt install -y nmap"
check nxc  "" "netexec/crackmapexec (AD/SMB)" "sudo apt install -y netexec"
check evil-winrm "" "evil-winrm (WinRM shell)" "sudo apt install -y evil-winrm"
check impacket-secretsdump "" "impacket (DCSync/secretsdump)" "sudo apt install -y impacket-scripts"
check ldapsearch "" "ldapsearch (AD LDAP)" "sudo apt install -y ldap-utils"
check kinit "" "kinit (Kerberos)" "sudo apt install -y krb5-user"
check certipy "" "certipy (ADCS)" "pipx install certipy-ad"
check nuclei "" "nuclei (web)" "sudo apt install -y nuclei"
check searchsploit "" "searchsploit (offline CVE DB)" "see step 4"
check mysql "" "mysql client (DMZ DB)" "sudo apt install -y default-mysql-client"
check proxychains4 "" "proxychains4 (pivot)" "sudo apt install -y proxychains4"
check msfconsole "" "metasploit" "sudo apt install -y metasploit-framework"
check "" /opt/pentest-tools/SharpCollection "SharpCollection (Rubeus/Certify/SharpHound)" "git clone Flangvik/SharpCollection"
check "" /opt/pentest-tools/PEASS-ng "PEASS-ng (linpeas/winpeas)" "re-run setup.sh"
check "" /usr/share/seclists "SecLists wordlists" "sudo apt install -y seclists"
check "" /usr/share/wordlists/rockyou.txt "rockyou.txt" "gunzip /usr/share/wordlists/rockyou.txt.gz"

echo
echo "================= OFFLINE READINESS ================="
echo "  present: $ok   missing: $miss"
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "  !! steps that FAILED (retry while online):"
  printf '    - %s\n' "${FAILED[@]}"
fi
df -h / | awk 'NR==2{print "  disk /: "$4" free ("$5" used)"}'
echo "  REMINDER: finish all of this NOW — internet is cut after Day 1."
echo "===================================================="
