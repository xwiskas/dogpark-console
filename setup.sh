#!/usr/bin/env bash
# DOGPARK Console — Phase 0 setup.
# Run this ONCE, on the Kali box, WHILE INTERNET ACCESS IS STILL AVAILABLE.
# Internet is cut after Day 1 per the playbook — if you skip this now, you're stuck offline.
set -euo pipefail

echo "=== DOGPARK Console: Phase 0 setup ==="
echo "This installs the standard Kali pentest tools the console builds commands for."
echo "Run this NOW if you're online — it will not work once the lab goes offline."
echo

sudo apt update
sudo apt install -y \
    nmap \
    nikto \
    enum4linux \
    gobuster \
    ffuf \
    hydra \
    hashcat \
    john \
    smbclient \
    smbmap \
    crackmapexec \
    impacket-scripts \
    wireshark \
    tcpdump \
    arpwatch \
    netcat-openbsd \
    socat

echo
echo "=== Wordlists ==="
if [ -f /usr/share/wordlists/rockyou.txt.gz ] && [ ! -f /usr/share/wordlists/rockyou.txt ]; then
    echo "Unzipping rockyou.txt.gz ..."
    sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz
else
    echo "rockyou.txt already present or not found — check /usr/share/wordlists/ manually."
fi

echo
echo "=== Output directories ==="
mkdir -p ~/dogpark/{runs,session,findings,loot,report}
echo "Created ~/dogpark/{runs,session,findings,loot,report}"

echo
echo "=== Done ==="
echo "REMINDER: this script must be run during Phase 0, while the lab still has internet"
echo "access. After Day 1, the network is cut and this script will fail."
