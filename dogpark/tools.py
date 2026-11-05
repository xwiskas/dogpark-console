"""Static tool/action registry — the catalog the GUI renders and builds commands from.

No subprocess calls here, no network, no filesystem access beyond nothing. Pure data plus
a small amount of string-formatting logic to turn an Action's template into a runnable
command once the user has filled in the placeholders.

Everything in this file is recon / enumeration / authenticated-login-testing / offline
cracking / passive capture / pivoting. There is intentionally nothing destructive, no DoS,
no flooding, no `--script dos`, no mass-exploit chains.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Optional

# Phase labels used by both the registry and the GUI's phase selector.
PHASES = {
    0: "Pre-engagement",
    1: "Subscreen",
    2: "Subscreen",
    3: "DMZ",
    4: "DMZ",
    5: "DMZ",
    6: "LAN",
    7: "LAN",
}

RISK_LEVELS = ("quiet", "normal", "loud")


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    phase: int
    description: str
    risk: str  # quiet | normal | loud
    template: str  # e.g. "nmap -T2 -sS {target} -oA {output}/nmap_{target}"
    needs: tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""

    def build_command(self, values: dict) -> str:
        """Render the template with the given input values. Missing optional fields are
        left as empty string rather than raising, so the preview field always shows
        something editable instead of crashing on a half-filled form."""
        safe_values = {}
        for key, val in values.items():
            if val is None:
                safe_values[key] = ""
            else:
                safe_values[key] = val
        for need in self.needs:
            safe_values.setdefault(need, "")
        try:
            return self.template.format(**safe_values)
        except (KeyError, IndexError):
            # A placeholder wasn't supplied at all — fall back to formatting against a
            # defaultdict-like mapping so the preview still renders (with blanks visible).
            class _Blank(dict):
                def __missing__(self, key):
                    return ""

            return self.template.format_map(_Blank(safe_values))


@dataclass(frozen=True)
class Tool:
    name: str
    binary: str
    category: str
    phases: tuple[int, ...]
    summary: str
    when_to_use: str
    actions: tuple[Action, ...]


def _quote(s: str) -> str:
    """Shell-quote a value for inclusion in a template (POSIX, matches the Kali target)."""
    if s is None:
        return ""
    return shlex.quote(str(s))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

TOOLS: tuple[Tool, ...] = (
    Tool(
        name="Host discovery",
        binary="nmap",
        category="discovery",
        phases=(1, 2, 3, 4, 5, 6, 7),
        summary="Find what's alive on the in-scope subnet before touching anything else.",
        when_to_use="Start of every phase: know the blue-team's footprint before enumerating services.",
        actions=(
            Action(
                id="discover.ping_sweep",
                label="Ping sweep (-sn)",
                phase=1,
                description="Host-discovery-only nmap sweep of a subnet/CIDR — no port scan, just who answers.",
                risk="quiet",
                template="nmap -sn {target} -oA {output}/discover_sweep",
                needs=("target", "output"),
            ),
            Action(
                id="discover.broadcast_scripts",
                label="Broadcast discovery scripts (arp-scan alternative)",
                phase=1,
                description="nmap's broadcast NSE scripts (ARP ping, DHCP discover, etc.) as a passive-ish "
                "arp-scan substitute when arp-scan isn't installed.",
                risk="quiet",
                template="nmap --script broadcast-ping -e {iface} -oA {output}/discover_broadcast",
                needs=("iface", "output"),
            ),
            Action(
                id="discover.ip_neigh",
                label="ARP/neighbor table note (ip neigh)",
                phase=1,
                description="Passive read of the local ARP/neighbor cache — zero packets sent, just notes "
                "who you've already talked to.",
                risk="quiet",
                template="ip neigh show",
                needs=(),
            ),
        ),
    ),
    Tool(
        name="nmap",
        binary="nmap",
        category="scan",
        phases=(1, 2, 3, 4, 5, 6, 7),
        summary="Port/service/version/script scanning.",
        when_to_use="Once a host is known-alive, learn what's listening and what's running.",
        actions=(
            Action(
                id="nmap.quiet_top_ports",
                label="Quiet top-ports scan (-T2 -sS)",
                phase=3,
                description="Stealthier SYN scan of the top ports at a slow timing template. Lower chance "
                "of tripping IDS thresholds.",
                risk="quiet",
                template="nmap -T2 -sS {target} -p {ports} -oA {output}/nmap_quiet_{target}",
                needs=("target", "ports", "output"),
            ),
            Action(
                id="nmap.full_version_scripts",
                label="Full version+scripts scan (-T4 -A)",
                phase=3,
                description="Aggressive timing, OS/version detection, and default NSE scripts. Loud but "
                "thorough — use once stealth no longer matters for this host.",
                risk="loud",
                template="nmap -T4 -A -p {ports} {target} -oA {output}/nmap_full_{target}",
                needs=("target", "ports", "output"),
            ),
            Action(
                id="nmap.max_rate_capped",
                label="Rate-capped full-port scan",
                phase=3,
                description="All 65535 ports with a conservative --max-rate so the switch/IDS doesn't choke; "
                "a middle ground between quiet and full -A.",
                risk="normal",
                template="nmap -p- --max-rate 300 {target} -oA {output}/nmap_allports_{target}",
                needs=("target", "output"),
            ),
        ),
    ),
    Tool(
        name="nikto",
        binary="nikto",
        category="web",
        phases=(3, 4, 5),
        summary="Web server scanner — checks for known-bad files, misconfig, outdated software banners.",
        when_to_use="Any HTTP/HTTPS service found during port scanning.",
        actions=(
            Action(
                id="nikto.basic",
                label="Basic web scan",
                phase=3,
                description="Standard nikto pass against a single URL/host, tee'd to an evidence file.",
                risk="normal",
                template="nikto -h {url} -output {output}/nikto_{target}.txt",
                needs=("url", "target", "output"),
            ),
        ),
    ),
    Tool(
        name="gobuster",
        binary="gobuster",
        category="web",
        phases=(3, 4, 5),
        summary="Directory / vhost brute-forcing against a wordlist.",
        when_to_use="Enumerating hidden paths or virtual hosts on a web server already found by nmap/nikto.",
        actions=(
            Action(
                id="gobuster.dir",
                label="Directory brute force",
                phase=3,
                description="Walks a wordlist against a URL path looking for valid directories/files.",
                risk="normal",
                template="gobuster dir -u {url} -w {wordlist} -o {output}/gobuster_dir_{target}.txt",
                needs=("url", "wordlist", "output", "target"),
            ),
            Action(
                id="gobuster.vhost",
                label="Virtual host brute force",
                phase=3,
                description="Looks for additional vhosts behind the same IP using Host-header fuzzing.",
                risk="normal",
                template="gobuster vhost -u {url} -w {wordlist} -o {output}/gobuster_vhost_{target}.txt",
                needs=("url", "wordlist", "output", "target"),
            ),
        ),
    ),
    Tool(
        name="ffuf",
        binary="ffuf",
        category="web",
        phases=(3, 4, 5),
        summary="Fast web fuzzer — alternative to gobuster with more flexible matching.",
        when_to_use="Same situations as gobuster; useful when you need filtered fuzzing (status/size/words).",
        actions=(
            Action(
                id="ffuf.dir",
                label="Directory fuzz",
                phase=3,
                description="Fuzzes the FUZZ keyword in a URL path against a wordlist.",
                risk="normal",
                template="ffuf -u {url}/FUZZ -w {wordlist} -o {output}/ffuf_{target}.json",
                needs=("url", "wordlist", "output", "target"),
            ),
        ),
    ),
    Tool(
        name="enum4linux",
        binary="enum4linux",
        category="smb",
        phases=(3, 4, 5, 6, 7),
        summary="SMB/NetBIOS/AD enumeration (users, shares, groups, policy).",
        when_to_use="Any Windows/Samba host; especially useful before trying credentials elsewhere.",
        actions=(
            Action(
                id="enum4linux.null_session",
                label="Null-session enumeration",
                phase=3,
                description="Anonymous/null-session enumeration of shares, users, and policy — no creds needed.",
                risk="quiet",
                template="enum4linux -a {target} | tee {output}/enum4linux_{target}.txt",
                needs=("target", "output"),
            ),
            Action(
                id="enum4linux.authed",
                label="Authenticated enumeration",
                phase=4,
                description="Same enumeration but with supplied credentials — fuller results on hardened hosts.",
                risk="normal",
                template="enum4linux -u {username} -p {password} -a {target} | tee {output}/enum4linux_auth_{target}.txt",
                needs=("target", "username", "password", "output"),
            ),
        ),
    ),
    Tool(
        name="smbclient",
        binary="smbclient",
        category="smb",
        phases=(3, 4, 5, 6, 7),
        summary="Interactive/scripted SMB share browsing.",
        when_to_use="Listing or pulling files from a share you already have (or lack) credentials for.",
        actions=(
            Action(
                id="smbclient.list_shares",
                label="List shares (null session)",
                phase=3,
                description="Lists available shares on a host with no credentials supplied.",
                risk="quiet",
                template="smbclient -L {target} -N | tee {output}/smbclient_list_{target}.txt",
                needs=("target", "output"),
            ),
            Action(
                id="smbclient.authed_list",
                label="List shares (authenticated)",
                phase=4,
                description="Lists shares using a supplied username/password.",
                risk="normal",
                template="smbclient -L {target} -U {username}%{password} | tee {output}/smbclient_list_auth_{target}.txt",
                needs=("target", "username", "password", "output"),
            ),
        ),
    ),
    Tool(
        name="smbmap",
        binary="smbmap",
        category="smb",
        phases=(3, 4, 5, 6, 7),
        summary="SMB share enumeration with permission mapping.",
        when_to_use="Quickly see read/write permissions across all shares on a host.",
        actions=(
            Action(
                id="smbmap.enum",
                label="Enumerate share permissions",
                phase=4,
                description="Shows every share on the host plus read/write permission for the given creds.",
                risk="normal",
                template="smbmap -H {target} -u {username} -p {password} | tee {output}/smbmap_{target}.txt",
                needs=("target", "username", "password", "output"),
            ),
        ),
    ),
    Tool(
        name="crackmapexec",
        binary="crackmapexec",
        category="smb",
        phases=(4, 5, 6, 7),
        summary="Swiss-army knife for SMB/AD enumeration and credential validation across hosts.",
        when_to_use="Spraying a known credential against the subnet to find reuse, or pulling logged-on users.",
        actions=(
            Action(
                id="cme.smb_creds_check",
                label="Validate credentials against a host",
                phase=4,
                description="Checks whether a username/password is valid on the target via SMB auth (no "
                "command execution). Useful for confirming creds before using them elsewhere.",
                risk="normal",
                template="crackmapexec smb {target} -u {username} -p {password} | tee {output}/cme_{target}.txt",
                needs=("target", "username", "password", "output"),
            ),
            Action(
                id="cme.logged_on_users",
                label="Logged-on users",
                phase=5,
                description="Lists currently logged-on users via SMB using validated credentials.",
                risk="normal",
                template="crackmapexec smb {target} -u {username} -p {password} --lusers | tee {output}/cme_lusers_{target}.txt",
                needs=("target", "username", "password", "output"),
            ),
        ),
    ),
    Tool(
        name="impacket-scripts",
        binary="impacket",
        category="ad",
        phases=(5, 6, 7),
        summary="Kerberos/AD enumeration and credential-dumping scripts (GetUserSPNs, secretsdump, psexec).",
        when_to_use="After you have at least one valid domain credential; Kerberoasting and lateral movement.",
        actions=(
            Action(
                id="impacket.getuserspns",
                label="GetUserSPNs — Kerberoasting enumeration",
                phase=5,
                description="Requests service tickets for SPN accounts for offline cracking. Requires a "
                "valid domain credential. Does not run exploit code on the target.",
                risk="normal",
                template="impacket-GetUserSPNs {domain}/{username}:{password} -dc-ip {target} -request "
                "-outputfile {output}/spns_{target}.txt",
                needs=("domain", "username", "password", "target", "output"),
                notes="Requires creds — label clearly as authenticated AD enumeration.",
            ),
            Action(
                id="impacket.secretsdump",
                label="secretsdump — credential extraction",
                phase=6,
                description="Dumps local/domain secrets (SAM/LSA/NTDS) using a valid privileged credential. "
                "Authenticated, not a vulnerability exploit.",
                risk="loud",
                template="impacket-secretsdump {domain}/{username}:{password}@{target} -outputfile "
                "{output}/secretsdump_{target}",
                needs=("domain", "username", "password", "target", "output"),
                notes="Requires admin/privileged creds. Redact output before screenshots.",
            ),
            Action(
                id="impacket.psexec",
                label="psexec — authenticated remote shell",
                phase=6,
                description="Opens a remote shell on a host using a valid administrative credential (SMB/RPC). "
                "This is a legitimate admin tool, not a new exploit — requires creds you already hold.",
                risk="loud",
                template="impacket-psexec {domain}/{username}:{password}@{target}",
                needs=("domain", "username", "password", "target"),
                notes="Requires admin creds. Only against in-scope hosts you're authorized to pivot through.",
            ),
        ),
    ),
    Tool(
        name="hydra",
        binary="hydra",
        category="auth",
        phases=(3, 4, 5, 6, 7),
        summary="Online service login brute force (SSH, FTP, HTTP forms, SMB, etc.).",
        when_to_use="Testing weak-credential exposure on a specific service, respecting lockout policy.",
        actions=(
            Action(
                id="hydra.ssh_conservative",
                label="SSH login test (conservative rate)",
                phase=4,
                description="Tries a userlist against a wordlist over SSH with a low task count to respect "
                "account-lockout thresholds. Note: check the lab's lockout policy before running — stop "
                "immediately if you see lockout indicators.",
                risk="normal",
                template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 ssh://{target}",
                needs=("userlist", "wordlist", "target"),
                notes="Respect lockout. Default -t 4 is intentionally conservative, not a flood.",
            ),
            Action(
                id="hydra.http_form",
                label="HTTP form login test",
                phase=4,
                description="Tries credentials against an HTTP login form with a conservative task count.",
                risk="normal",
                template='hydra -L {userlist} -P {wordlist} -t 4 {target} http-post-form "{url}"',
                needs=("userlist", "wordlist", "target", "url"),
                notes="Respect lockout policy.",
            ),
        ),
    ),
    Tool(
        name="john",
        binary="john",
        category="cracking",
        phases=(4, 5, 6, 7),
        summary="Offline password-hash cracking.",
        when_to_use="You've got a hash dump (e.g. from secretsdump) and want to recover plaintext offline.",
        actions=(
            Action(
                id="john.wordlist",
                label="Wordlist crack",
                phase=5,
                description="Runs john against a hash file using a wordlist. Fully offline — no network "
                "traffic to any host.",
                risk="quiet",
                template="john --wordlist={wordlist} {hashfile}",
                needs=("wordlist", "hashfile"),
            ),
            Action(
                id="john.show",
                label="Show cracked results",
                phase=5,
                description="Prints previously-cracked results for a hash file.",
                risk="quiet",
                template="john --show {hashfile}",
                needs=("hashfile",),
            ),
        ),
    ),
    Tool(
        name="hashcat",
        binary="hashcat",
        category="cracking",
        phases=(4, 5, 6, 7),
        summary="GPU-accelerated offline password-hash cracking.",
        when_to_use="Same as john, faster on supported hash types with a GPU available.",
        actions=(
            Action(
                id="hashcat.wordlist",
                label="Wordlist crack",
                phase=5,
                description="Runs hashcat against a hash file with a wordlist and a mode (-m) you set per "
                "hash type. Fully offline.",
                risk="quiet",
                template="hashcat -m {hashmode} {hashfile} {wordlist} -o {output}/hashcat_cracked.txt",
                needs=("hashmode", "hashfile", "wordlist", "output"),
            ),
        ),
    ),
    Tool(
        name="tcpdump",
        binary="tcpdump",
        category="capture",
        phases=(1, 2, 3, 4, 5, 6, 7),
        summary="Passive packet capture to a file.",
        when_to_use="Capturing traffic on an interface for later analysis — never injects/sends traffic.",
        actions=(
            Action(
                id="tcpdump.capture",
                label="Capture to file",
                phase=1,
                description="Passive capture on an interface, written to a pcap for later Wireshark review.",
                risk="quiet",
                template="tcpdump -i {iface} -w {output}/capture_{target}.pcap",
                needs=("iface", "output", "target"),
            ),
        ),
    ),
    Tool(
        name="wireshark",
        binary="wireshark",
        category="capture",
        phases=(1, 2, 3, 4, 5, 6, 7),
        summary="GUI packet analyzer — usually used to open a capture made by tcpdump.",
        when_to_use="Reviewing a pcap file in depth with protocol dissectors and filters.",
        actions=(
            Action(
                id="wireshark.open_capture",
                label="Open a capture file",
                phase=1,
                description="Opens an existing pcap in the Wireshark GUI for analysis. Does not itself "
                "capture or send traffic.",
                risk="quiet",
                template="wireshark -r {output}/capture_{target}.pcap",
                needs=("output", "target"),
            ),
        ),
    ),
    Tool(
        name="arpwatch",
        binary="arpwatch",
        category="capture",
        phases=(1, 2, 3),
        summary="Passive ARP activity monitor — flags new/changed MAC-to-IP pairings.",
        when_to_use="Watching for new hosts appearing on the local segment without active scanning.",
        actions=(
            Action(
                id="arpwatch.monitor",
                label="Monitor interface",
                phase=1,
                description="Passively logs ARP traffic on an interface to a syslog/file for later review.",
                risk="quiet",
                template="arpwatch -i {iface} -f {output}/arpwatch_{iface}.log",
                needs=("iface", "output"),
            ),
        ),
    ),
    Tool(
        name="netcat",
        binary="nc",
        category="pivot",
        phases=(5, 6, 7),
        summary="Listener / connect / simple file transfer between in-scope hosts.",
        when_to_use="Moving loot between hosts you already control, or setting up a basic pivot listener.",
        actions=(
            Action(
                id="netcat.listener",
                label="Start a listener",
                phase=6,
                description="Opens a TCP listener on a port, logging anything received to a file. Used for "
                "catching callbacks or receiving file transfers from an in-scope host.",
                risk="normal",
                template="nc -lvnp {port} > {output}/nc_listener_{port}.log",
                needs=("port", "output"),
            ),
            Action(
                id="netcat.connect",
                label="Connect to a listener",
                phase=6,
                description="Connects out to a listener on another in-scope host.",
                risk="normal",
                template="nc {target} {port}",
                needs=("target", "port"),
            ),
            Action(
                id="netcat.file_send",
                label="Send a file",
                phase=6,
                description="Streams a local file to a listening nc on the target host.",
                risk="normal",
                template="nc {target} {port} < {loot_file}",
                needs=("target", "port", "loot_file"),
            ),
        ),
    ),
    Tool(
        name="socat",
        binary="socat",
        category="pivot",
        phases=(5, 6, 7),
        summary="Flexible relay/listener — richer netcat alternative for pivoting.",
        when_to_use="Relaying traffic between two in-scope hosts, e.g. port-forwarding through a pivot box.",
        actions=(
            Action(
                id="socat.tcp_relay",
                label="TCP relay (port forward)",
                phase=6,
                description="Relays connections on a local port to a remote in-scope host:port — a simple "
                "pivot/port-forward.",
                risk="normal",
                template="socat TCP-LISTEN:{port},fork TCP:{target}:{remote_port}",
                needs=("port", "target", "remote_port"),
            ),
        ),
    ),
)


def _load_catalog_extras() -> dict[str, tuple[Action, ...]]:
    """Collect EXTRA_ACTIONS from every module in the optional dogpark.catalog package.

    Each catalog module (one per tool group) may define
    ``EXTRA_ACTIONS: dict[str, tuple[Action, ...]]`` mapping a Tool.name to extra actions.
    This lets the command library grow in separate, conflict-free files. Import errors or a
    missing package are ignored so the base registry always works on its own. No network or
    side effects — just importing sibling data modules.
    """
    import importlib
    import pkgutil

    merged: dict[str, list[Action]] = {}
    try:
        from . import catalog  # type: ignore
    except Exception:
        return {}
    for info in pkgutil.iter_modules(catalog.__path__):
        try:
            mod = importlib.import_module(f"{catalog.__name__}.{info.name}")
        except Exception:
            continue
        extras = getattr(mod, "EXTRA_ACTIONS", None)
        if not isinstance(extras, dict):
            continue
        for tool_name, actions in extras.items():
            merged.setdefault(tool_name, []).extend(actions)
    return {k: tuple(v) for k, v in merged.items()}


def _merge_extras(base: tuple[Tool, ...]) -> tuple[Tool, ...]:
    """Return base tools with any catalog EXTRA_ACTIONS appended, de-duped by action id."""
    import dataclasses

    extras = _load_catalog_extras()
    if not extras:
        return base
    out: list[Tool] = []
    for tool in base:
        add = extras.get(tool.name)
        if not add:
            out.append(tool)
            continue
        seen = {a.id for a in tool.actions}
        new_actions = tool.actions + tuple(a for a in add if a.id not in seen)
        out.append(dataclasses.replace(tool, actions=new_actions))
    return tuple(out)


# Base registry defined above as the literal tuple; fold in any per-group catalog modules.
TOOLS = _merge_extras(TOOLS)


def all_tools() -> tuple[Tool, ...]:
    return TOOLS


def tools_for_phase(phase: int) -> list[Tool]:
    """Tools that have at least one action relevant to the given phase."""
    return [t for t in TOOLS if phase in t.phases]


def find_action(action_id: str) -> Optional[tuple[Tool, Action]]:
    for tool in TOOLS:
        for action in tool.actions:
            if action.id == action_id:
                return tool, action
    return None
