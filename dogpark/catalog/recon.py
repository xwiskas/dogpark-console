"""Deep command catalog for the RECON group: nmap and Host discovery.

Operation DOGPARK is an authorized, isolated CSUSB cyberlab red-team class exercise.
This module is a guided reference library over standard Kali tools already installed on
the student's Kali VM — it organizes and explains commands and builds them for the user
to review and run manually. Nothing here executes code, makes network calls, or does
anything beyond building a command string.

Scope is strictly recon / enumeration / host discovery. Nothing destructive: no DoS, no
flooding, no `--script dos`, no exploit/intrusive brute forcing that could knock over a
host. Every NSE category used below (discovery, auth, default, vuln — read-only checks)
is a passive/informational check, never dos/exploit/intrusive.
"""

from __future__ import annotations

from dogpark.tools import Action

EXTRA_ACTIONS: dict[str, tuple[Action, ...]] = {
    # -------------------------------------------------------------------
    # nmap — full scan-type / timing / detection / evasion library
    # -------------------------------------------------------------------
    "nmap": (
        Action(
            id="nmap.syn_stealth",
            label="SYN stealth scan (-sS)",
            phase=1,
            description="The classic half-open SYN scan. Doesn't complete the TCP handshake, so it's "
            "faster and a bit less visible in connection logs than a full connect scan. The default "
            "choice for most port discovery when you have raw-socket privileges.",
            risk="normal",
            template="nmap -sS {target} -p {ports} -oA {output}/nmap_syn_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.connect_scan",
            label="TCP connect scan (-sT)",
            phase=1,
            description="Full TCP three-way handshake per port. Use when you lack raw-socket privileges "
            "(no root) or are scanning through a proxy — slower and more visible in logs than -sS.",
            risk="normal",
            template="nmap -sT {target} -p {ports} -oA {output}/nmap_connect_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.udp_scan",
            label="UDP scan (-sU)",
            phase=1,
            description="Probes UDP ports (DNS, SNMP, DHCP, etc). Much slower than TCP scans because of "
            "ICMP rate limiting — pair with a small, specific port list rather than scanning every port.",
            risk="normal",
            template="nmap -sU {target} -p {ports} -oA {output}/nmap_udp_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.ack_scan",
            label="ACK scan (-sA)",
            phase=1,
            description="Sends bare ACK packets to map firewall rule sets — distinguishes filtered from "
            "unfiltered ports without ever completing a handshake. Doesn't reliably report open vs. "
            "closed, only filtered vs. unfiltered.",
            risk="quiet",
            template="nmap -sA {target} -p {ports} -oA {output}/nmap_ack_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.ping_sweep_cidr",
            label="Ping sweep a subnet (-sn)",
            phase=1,
            description="Host-discovery-only pass across an entire CIDR range with no port scan — the "
            "fastest way to find which addresses are alive before enumerating anything further.",
            risk="quiet",
            template="nmap -sn {target} -oA {output}/nmap_sweep",
            needs=("target", "output"),
        ),
        Action(
            id="nmap.timing_t0_paranoid",
            label="Paranoid timing (-T0)",
            phase=1,
            description="Slowest built-in timing template — serializes probes with long waits between "
            "them to stay under IDS detection thresholds. Can take hours for a handful of ports; use "
            "only when stealth matters more than speed.",
            risk="quiet",
            template="nmap -T0 -sS {target} -p {ports} -oA {output}/nmap_t0_{target}",
            needs=("target", "ports", "output"),
            notes="Extremely slow — a full scan can take hours. Plan accordingly.",
        ),
        Action(
            id="nmap.timing_t1_sneaky",
            label="Sneaky timing (-T1)",
            phase=1,
            description="Second-slowest timing template. Still deliberately throttled to avoid IDS "
            "thresholds, but faster than -T0.",
            risk="quiet",
            template="nmap -T1 -sS {target} -p {ports} -oA {output}/nmap_t1_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.timing_t2_polite",
            label="Polite timing (-T2)",
            phase=1,
            description="Slows down to use less bandwidth and fewer target resources than defaults — "
            "a reasonable middle ground when you want to be considerate without going fully paranoid.",
            risk="quiet",
            template="nmap -T2 -sS {target} -p {ports} -oA {output}/nmap_t2_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.timing_t3_normal",
            label="Normal timing (-T3, default)",
            phase=1,
            description="nmap's default timing — balances speed and reliability without any special "
            "throttling or aggression. The baseline for everyday scanning.",
            risk="normal",
            template="nmap -T3 -sS {target} -p {ports} -oA {output}/nmap_t3_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.timing_t4_aggressive",
            label="Aggressive timing (-T4)",
            phase=1,
            description="Assumes a fast, reliable network and speeds up probes accordingly. Good for "
            "well-behaved lab networks; noisier and more likely to trip IDS/rate-limit alarms.",
            risk="loud",
            template="nmap -T4 -sS {target} -p {ports} -oA {output}/nmap_t4_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.timing_t5_insane",
            label="Insane timing (-T5)",
            phase=1,
            description="Fastest, most aggressive built-in timing — sacrifices accuracy for speed and is "
            "very loud. Use only on a known-robust lab network when speed matters more than stealth.",
            risk="loud",
            template="nmap -T5 -sS {target} -p {ports} -oA {output}/nmap_t5_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.service_version",
            label="Service/version detection (-sV)",
            phase=1,
            description="Probes open ports to identify the service and version banner running on each. "
            "Essential for matching findings to known CVEs later.",
            risk="normal",
            template="nmap -sV {target} -p {ports} -oA {output}/nmap_sv_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.os_detection",
            label="OS detection (-O)",
            phase=1,
            description="Fingerprints TCP/IP stack behavior to guess the target's OS and kernel version. "
            "Sends a handful of extra probes beyond a normal port scan.",
            risk="normal",
            template="nmap -O {target} -oA {output}/nmap_os_{target}",
            needs=("target", "output"),
        ),
        Action(
            id="nmap.default_safe_scripts",
            label="Default safe NSE scripts (-sC)",
            phase=1,
            description="Runs nmap's 'default' NSE script category — a curated set of safe, non-intrusive "
            "scripts (banner grabs, common misconfig checks) that run automatically with -sV.",
            risk="normal",
            template="nmap -sC -sV {target} -p {ports} -oA {output}/nmap_sc_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.nse_discovery",
            label="NSE discovery category",
            phase=1,
            description="Runs the 'discovery' NSE script category — enumerates extra host/service info "
            "(e.g. SNMP, SMB shares, DNS) beyond the default set. Read-only enumeration, not exploitation.",
            risk="normal",
            template="nmap --script discovery {target} -p {ports} -oA {output}/nmap_nse_discovery_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.nse_auth",
            label="NSE auth category",
            phase=1,
            description="Runs the 'auth' NSE script category — checks for default/blank credentials and "
            "weak auth config without attempting to brute force anything.",
            risk="normal",
            template="nmap --script auth {target} -p {ports} -oA {output}/nmap_nse_auth_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.nse_default",
            label="NSE default category",
            phase=1,
            description="Explicitly runs the 'default' NSE category by name (same scripts as -sC) — "
            "useful when you want the category spelled out alongside other --script flags.",
            risk="normal",
            template="nmap --script default {target} -p {ports} -oA {output}/nmap_nse_default_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.nse_vuln",
            label="NSE vuln+safe scripts (detection only)",
            phase=1,
            description="Runs NSE scripts tagged both 'vuln' and 'safe', which check for and report "
            "known vulnerabilities without exploiting or disrupting the target. Detection and "
            "enumeration only; disruptive and intrusive script categories are excluded.",
            risk="normal",
            template="nmap --script \"vuln and safe\" {target} -p {ports} -oA {output}/nmap_nse_vuln_{target}",
            needs=("target", "ports", "output"),
            notes="Restricted to scripts tagged both 'vuln' and 'safe' so the scan stays non-disruptive.",
        ),
        Action(
            id="nmap.top_ports",
            label="Top N ports (--top-ports)",
            phase=1,
            description="Scans only the N most commonly open ports instead of a full range — a fast first "
            "pass to find low-hanging fruit before committing to a full scan.",
            risk="quiet",
            template="nmap --top-ports {top_n} {target} -oA {output}/nmap_top_{target}",
            needs=("top_n", "target", "output"),
        ),
        Action(
            id="nmap.all_ports",
            label="Full port range (-p-)",
            phase=1,
            description="Scans the entire 1-65535 TCP port range. Thorough but slow and noisy — run it "
            "once you've decided a host is worth the full treatment.",
            risk="loud",
            template="nmap -p- {target} -oA {output}/nmap_allports_{target}",
            needs=("target", "output"),
        ),
        Action(
            id="nmap.specific_ports",
            label="Specific port list",
            phase=1,
            description="Scans only an explicit, comma-separated port list you already care about — "
            "fastest and quietest way to re-check a small set of known services.",
            risk="quiet",
            template="nmap -p {ports} {target} -oA {output}/nmap_ports_{target}",
            needs=("ports", "target", "output"),
        ),
        Action(
            id="nmap.output_normal",
            label="Normal-format output (-oN)",
            phase=1,
            description="Writes results in nmap's plain human-readable format only, instead of the full "
            "-oA trio (normal/XML/grepable). Handy for a quick, single-file log.",
            risk="quiet",
            template="nmap {target} -p {ports} -oN {output}/nmap_normal_{target}.txt",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.output_grepable",
            label="Grepable output (-oG)",
            phase=1,
            description="Writes results in the line-oriented grepable format, convenient for piping into "
            "grep/awk scripts for later automated triage.",
            risk="quiet",
            template="nmap {target} -p {ports} -oG {output}/nmap_grepable_{target}.gnmap",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.output_all_formats",
            label="All output formats (-oA)",
            phase=1,
            description="Writes results in all three formats (normal, XML, grepable) at once under a "
            "shared basename — the usual choice when you want full flexibility for later tooling.",
            risk="quiet",
            template="nmap {target} -p {ports} -oA {output}/nmap_full_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.fragment_packets",
            label="Fragment packets (-f)",
            phase=1,
            description="Splits probe packets into smaller IP fragments to slip past some packet-filtering "
            "firewalls and simple IDS signature matching. Purely a transport-layer evasion trick, not an "
            "exploit.",
            risk="quiet",
            template="nmap -f -sS {target} -p {ports} -oA {output}/nmap_frag_{target}",
            needs=("target", "ports", "output"),
            notes="Some stateful firewalls reassemble fragments anyway, reducing the benefit.",
        ),
        Action(
            id="nmap.custom_mtu",
            label="Custom MTU (--mtu)",
            phase=1,
            description="Sets a specific fragment size (must be a multiple of 8) instead of nmap's default "
            "-f fragmentation, giving finer control over how probes are split for evasion.",
            risk="quiet",
            template="nmap --mtu {mtu} -sS {target} -p {ports} -oA {output}/nmap_mtu_{target}",
            needs=("mtu", "target", "ports", "output"),
        ),
        Action(
            id="nmap.decoy_scan",
            label="Decoy scan (-D)",
            phase=1,
            description="Spoofs additional decoy source addresses alongside your real one, so the "
            "target's logs show several apparent scanners instead of just you. Decoys should be real, "
            "responsive hosts or the technique can look suspicious on its own.",
            risk="quiet",
            template="nmap -D {decoys} -sS {target} -p {ports} -oA {output}/nmap_decoy_{target}",
            needs=("decoys", "target", "ports", "output"),
            notes="Only use decoy IPs that are in-scope/approved for this exercise.",
        ),
        Action(
            id="nmap.source_port_spoof",
            label="Spoof source port (--source-port)",
            phase=1,
            description="Sends probes from a specific source port (e.g. 53 or 88) to blend in with "
            "trusted traffic that some poorly-configured firewalls allow through unconditionally.",
            risk="quiet",
            template="nmap --source-port {source_port} -sS {target} -p {ports} -oA {output}/nmap_srcport_{target}",
            needs=("source_port", "target", "ports", "output"),
        ),
        Action(
            id="nmap.custom_data_length",
            label="Append random data (--data-length)",
            phase=1,
            description="Pads probe packets with extra random-length data so they don't match the "
            "default nmap packet-size signature some IDS rules key off of.",
            risk="quiet",
            template="nmap --data-length {data_length} -sS {target} -p {ports} -oA {output}/nmap_datalen_{target}",
            needs=("data_length", "target", "ports", "output"),
        ),
        Action(
            id="nmap.scan_delay",
            label="Slow-and-quiet scan delay (--scan-delay)",
            phase=1,
            description="Forces a minimum wait between consecutive probes, independent of the timing "
            "template — the most direct knob for staying under per-second request thresholds that trigger "
            "alerting.",
            risk="quiet",
            template="nmap --scan-delay {scan_delay} -sS {target} -p {ports} -oA {output}/nmap_delay_{target}",
            needs=("scan_delay", "target", "ports", "output"),
        ),
        Action(
            id="nmap.max_rate_cap",
            label="Rate-capped scan (--max-rate)",
            phase=1,
            description="Caps outbound packet rate so a full-range scan doesn't overwhelm a fragile "
            "switch/IDS — a middle ground between quiet single-probe delay and an uncapped fast scan.",
            risk="normal",
            template="nmap -p- --max-rate {max_rate} {target} -oA {output}/nmap_maxrate_{target}",
            needs=("max_rate", "target", "output"),
        ),
        Action(
            id="nmap.no_ping",
            label="Skip host discovery (-Pn)",
            phase=1,
            description="Treats the target as online and skips the initial ping/discovery probe entirely — "
            "useful against hosts that drop ICMP/ping but still have open ports, though it means you'll "
            "scan ports even on genuinely dead hosts.",
            risk="quiet",
            template="nmap -Pn -sS {target} -p {ports} -oA {output}/nmap_pn_{target}",
            needs=("target", "ports", "output"),
        ),
        Action(
            id="nmap.quiet_evasion_combo",
            label="Combined stealth/evasion scan",
            phase=1,
            description="Stacks several evasion techniques together — slow timing, fragmentation, a "
            "spoofed source port, and -Pn — for the quietest practical scan this catalog offers. Trades "
            "a lot of speed for a much smaller footprint.",
            risk="quiet",
            template="nmap -T1 -f -Pn --source-port {source_port} -sS {target} -p {ports} "
            "-oA {output}/nmap_stealth_combo_{target}",
            needs=("source_port", "target", "ports", "output"),
            notes="Still sends real probes from your real address — this is footprint reduction, not "
            "anonymity.",
        ),
    ),
    # -------------------------------------------------------------------
    # Host discovery — finding the blue team's IP(s) on the in-scope subnet
    # -------------------------------------------------------------------
    "Host discovery": (
        Action(
            id="discover.arp_scan_iface",
            label="arp-scan an interface",
            phase=1,
            description="Sends ARP requests to every address on the local subnet attached to an "
            "interface and lists who answers with their MAC vendor. Fast, reliable, and works even "
            "when ICMP is filtered — the usual first move to find live hosts on a local segment.",
            risk="quiet",
            template="arp-scan --interface={iface} {target} -oA {output}/arpscan_{iface}",
            needs=("iface", "target", "output"),
            notes="arp-scan's native output isn't -oA format; redirect its stdout to a file under "
            "{output} if you need a saved transcript.",
        ),
        Action(
            id="discover.arp_scan_localnet",
            label="arp-scan the whole local network",
            phase=1,
            description="Same ARP sweep but against every address on the interface's local network "
            "(--localnet) instead of a specific range — convenient when you don't know the exact CIDR "
            "yet.",
            risk="quiet",
            template="arp-scan --interface={iface} --localnet",
            needs=("iface",),
        ),
        Action(
            id="discover.netdiscover_active",
            label="netdiscover active scan",
            phase=1,
            description="Actively sends ARP requests across a range to build a live host list with "
            "vendor info, refreshing in real time — a GUI-less alternative to arp-scan for the same job.",
            risk="quiet",
            template="netdiscover -i {iface} -r {target}",
            needs=("iface", "target"),
        ),
        Action(
            id="discover.netdiscover_passive",
            label="netdiscover passive sniff",
            phase=1,
            description="Listens for ARP traffic already on the wire without sending any probes of its "
            "own — the quietest possible way to notice hosts, at the cost of only seeing who happens to "
            "talk while you're listening.",
            risk="quiet",
            template="netdiscover -i {iface} -p",
            needs=("iface",),
        ),
        Action(
            id="discover.fping_sweep",
            label="fping CIDR sweep",
            phase=1,
            description="Pings an entire CIDR range in parallel and reports which hosts respond — faster "
            "than scripting individual pings, though it depends on ICMP not being filtered.",
            risk="quiet",
            template="fping -a -g {target} 2>/dev/null | tee {output}/fping_{target}.txt",
            needs=("target", "output"),
        ),
        Action(
            id="discover.nmap_cidr_sweep",
            label="nmap CIDR ping sweep (-sn)",
            phase=1,
            description="nmap's own host-discovery-only sweep of a CIDR range — no ports touched, just "
            "which addresses answer to ARP/ICMP/TCP probes depending on what's reachable.",
            risk="quiet",
            template="nmap -sn {target} -oA {output}/discover_nmap_sweep",
            needs=("target", "output"),
        ),
        Action(
            id="discover.ip_neigh_table",
            label="Read local ARP/neighbor table (ip neigh)",
            phase=1,
            description="Passively prints the kernel's existing ARP/neighbor cache — zero packets sent, "
            "just a look at hosts you've already exchanged traffic with.",
            risk="quiet",
            template="ip neigh show",
            needs=(),
        ),
        Action(
            id="discover.arp_table_legacy",
            label="Read ARP table (arp -a)",
            phase=1,
            description="Legacy equivalent of 'ip neigh show' — lists the current ARP cache. Purely "
            "passive, no traffic generated.",
            risk="quiet",
            template="arp -a",
            needs=(),
        ),
        Action(
            id="discover.nmap_broadcast_scripts",
            label="nmap broadcast NSE discovery",
            phase=1,
            description="Runs nmap's broadcast-* NSE scripts (ARP ping, DHCP discover, broadcast ping, "
            "etc.) on an interface as an arp-scan/netdiscover substitute when neither tool is installed.",
            risk="quiet",
            template="nmap --script broadcast-ping -e {iface} -oA {output}/discover_broadcast_{iface}",
            needs=("iface", "output"),
        ),
    ),
}
