"""Deep command library for the CAPTURE/PIVOT group — Operation DOGPARK.

Covers tcpdump, wireshark/tshark, arpwatch, netcat and socat: passive packet
capture, offline pcap analysis, passive ARP/host monitoring, and in-lab
file movement / port-forwarding between hosts the student already controls.

Scope discipline, same as the base registry in dogpark.tools:
  - Capture and monitoring actions here are strictly passive (no injection,
    no traffic generation, no MITM/poisoning — no arpspoof, no ettercap).
  - Listener/relay/transfer actions only ever move data between in-scope
    lab hosts the student is authorized to pivot through. Nothing here
    floods, scans destructively, or targets anything out of scope.
  - This module is pure data: only `Action` is imported, no subprocess,
    no socket, no filesystem access. Building and running the resulting
    command string is the GUI/runner's job, after the student reviews it.

EXTRA_ACTIONS keys must match an existing Tool.name in dogpark.tools so the
loader in tools.py folds these actions into that tool's action tuple.
"""

from __future__ import annotations

from dogpark.tools import Action

EXTRA_ACTIONS: dict[str, tuple[Action, ...]] = {
    # ------------------------------------------------------------------
    # tcpdump — passive capture to file, read back, filter, rotate
    # ------------------------------------------------------------------
    "tcpdump": (
        Action(
            id="tcpdump.capture_no_dns",
            label="Capture to file, no DNS resolution (-n)",
            phase=1,
            description="Passive capture on an interface with -n so tcpdump doesn't reverse-resolve "
            "every address (faster, and avoids generating extra DNS traffic of its own).",
            risk="quiet",
            template="tcpdump -i {iface} -n -w {output}/cap.pcap",
            needs=("iface", "output"),
        ),
        Action(
            id="tcpdump.bpf_host",
            label="Filter on a single host (BPF host filter)",
            phase=1,
            description="Capture limited to traffic to/from one in-scope host — keeps the pcap focused "
            "on the box you care about instead of the whole segment.",
            risk="quiet",
            template="tcpdump -i {iface} -n host {target} -w {output}/cap_{target}.pcap",
            needs=("iface", "target", "output"),
        ),
        Action(
            id="tcpdump.bpf_port",
            label="Filter on a port (BPF port filter)",
            phase=1,
            description="Capture limited to a single service port — e.g. isolate HTTP/SMB/DNS traffic "
            "for a focused review pass.",
            risk="quiet",
            template="tcpdump -i {iface} -n port {port} -w {output}/cap_port_{port}.pcap",
            needs=("iface", "port", "output"),
        ),
        Action(
            id="tcpdump.bpf_net",
            label="Filter on a subnet (BPF net filter)",
            phase=1,
            description="Capture limited to a subnet/CIDR — useful when the interface sees more than "
            "one in-scope segment and you only want traffic from the lab range.",
            risk="quiet",
            template="tcpdump -i {iface} -n net {bpf} -w {output}/cap_net.pcap",
            needs=("iface", "bpf", "output"),
        ),
        Action(
            id="tcpdump.snaplen_count",
            label="Bounded capture (snaplen + packet count)",
            phase=1,
            description="Caps both the per-packet snapshot length (-s) and the total packet count (-c) "
            "so the capture stays small and finite — good for a quick spot-check.",
            risk="quiet",
            template="tcpdump -i {iface} -n -s {snaplen} -c {count} -w {output}/cap_sample.pcap",
            needs=("iface", "snaplen", "count", "output"),
        ),
        Action(
            id="tcpdump.read_pcap",
            label="Read back a saved pcap (-r)",
            phase=1,
            description="Offline read of a previously captured file — no interface touched, no traffic "
            "sent, just re-displaying what was already saved.",
            risk="quiet",
            template="tcpdump -n -r {file}",
            needs=("file",),
        ),
        Action(
            id="tcpdump.rotate_files",
            label="Rotate capture files by time (-G) and count",
            phase=1,
            description="Rotates to a new output file every -G seconds, keeping -W of them — for a "
            "long-running passive capture that shouldn't grow into one unbounded file.",
            risk="quiet",
            template="tcpdump -i {iface} -n -G {rotate_seconds} -W {rotate_count} -w {output}/cap_%Y%m%d_%H%M%S.pcap",
            needs=("iface", "rotate_seconds", "rotate_count", "output"),
        ),
        Action(
            id="tcpdump.ascii_hex",
            label="Print ASCII + hex of packet contents (-A -X)",
            phase=1,
            description="Dumps packet payloads in both ASCII and hex to the terminal/log — handy for "
            "eyeballing unencrypted protocol content (e.g. HTTP headers) while reviewing live.",
            risk="quiet",
            template="tcpdump -i {iface} -n -A -X port {port} | tee {output}/cap_ascii_hex_{port}.txt",
            needs=("iface", "port", "output"),
        ),
        Action(
            id="tcpdump.arp_only",
            label="ARP-only filter",
            phase=1,
            description="Captures only ARP traffic — a lightweight way to watch for new hosts or "
            "address changes on the segment without a full packet capture.",
            risk="quiet",
            template="tcpdump -i {iface} -n arp -w {output}/cap_arp.pcap",
            needs=("iface", "output"),
        ),
        Action(
            id="tcpdump.creds_interesting",
            label="Clear-text-credential-prone ports (FTP/Telnet/HTTP)",
            phase=1,
            description="Narrows the capture to ports that historically carry clear-text auth (21, 23, "
            "80) so a review pass can focus on where creds might be exposed in-scope.",
            risk="quiet",
            template="tcpdump -i {iface} -n port 21 or port 23 or port 80 -w {output}/cap_creds_watch.pcap",
            needs=("iface", "output"),
        ),
    ),
    # ------------------------------------------------------------------
    # wireshark / tshark — capture to file, filter, extract, follow
    # ------------------------------------------------------------------
    "wireshark": (
        Action(
            id="tshark.capture_to_file",
            label="tshark: capture to file (-w)",
            phase=1,
            description="Command-line capture equivalent to tcpdump -w, using tshark so the same tool "
            "chain handles both capture and later filtering/analysis.",
            risk="quiet",
            template="tshark -i {iface} -w {output}/cap.pcapng",
            needs=("iface", "output"),
        ),
        Action(
            id="tshark.read_with_display_filter",
            label="tshark: read pcap with display filter (-Y)",
            phase=1,
            description="Opens an existing capture and applies a Wireshark display filter (e.g. "
            "'http.request' or 'ip.addr==10.0.0.5') to pull out only matching packets.",
            risk="quiet",
            template="tshark -r {file} -Y {bpf}",
            needs=("file", "bpf"),
            notes="{bpf} here holds a Wireshark display-filter expression, not a BPF string.",
        ),
        Action(
            id="tshark.field_extraction",
            label="tshark: extract specific fields (-T fields -e)",
            phase=1,
            description="Pulls just the fields you name (e.g. ip.src, ip.dst, tcp.port) out of a "
            "capture into a flat table — good for quick triage or feeding another tool.",
            risk="quiet",
            template="tshark -r {file} -T fields -e ip.src -e ip.dst -e {bpf} > {output}/fields.csv",
            needs=("file", "bpf", "output"),
            notes="{bpf} holds the extra field name to extract alongside ip.src/ip.dst.",
        ),
        Action(
            id="tshark.follow_stream",
            label="tshark: follow a TCP stream",
            phase=1,
            description="Reassembles and prints one TCP conversation's payload — the CLI equivalent of "
            "Wireshark's 'Follow > TCP Stream', useful for reading a session's clear-text content.",
            risk="quiet",
            template="tshark -r {file} -q -z follow,tcp,ascii,{bpf}",
            needs=("file", "bpf"),
            notes="{bpf} holds the stream index (e.g. 0) from a prior tshark -r listing.",
        ),
        Action(
            id="tshark.ring_buffer",
            label="tshark: ring-buffer capture (-b)",
            phase=1,
            description="Long-running passive capture that rotates through a fixed set of files "
            "instead of growing without bound — same idea as tcpdump's -G/-W, tshark's own flag.",
            risk="quiet",
            template="tshark -i {iface} -b filesize:{snaplen} -b files:{rotate_count} -w {output}/ring.pcapng",
            needs=("iface", "snaplen", "rotate_count", "output"),
        ),
        Action(
            id="tshark.count_and_stop",
            label="tshark: capture a bounded packet count (-c)",
            phase=1,
            description="Stops automatically after -c packets — a quick, finite capture for a spot "
            "check rather than an open-ended run.",
            risk="quiet",
            template="tshark -i {iface} -c {count} -w {output}/cap_sample.pcapng",
            needs=("iface", "count", "output"),
        ),
        Action(
            id="wireshark.gui_open",
            label="Wireshark GUI: open a capture",
            phase=1,
            description="Opens the Wireshark GUI directly on an existing pcap for interactive "
            "dissection — use this instead of tshark when you want to click through packets by hand.",
            risk="quiet",
            template="wireshark -r {file}",
            needs=("file",),
            notes="GUI tool — only a note/launch command, nothing to build or review beyond the path.",
        ),
    ),
    # ------------------------------------------------------------------
    # arpwatch — passive ARP/host monitoring
    # ------------------------------------------------------------------
    "arpwatch": (
        Action(
            id="arpwatch.new_station_log",
            label="Monitor for new MAC/IP pairings",
            phase=1,
            description="Runs arpwatch against an interface and reports when a MAC address is seen for "
            "the first time, or paired with a new IP — a passive way to notice new hosts joining the "
            "segment.",
            risk="quiet",
            template="arpwatch -i {iface} -f {output}/arpwatch_new_{iface}.log",
            needs=("iface", "output"),
        ),
        Action(
            id="arpwatch.flip_flop_log",
            label="Monitor for ARP flip-flops / anomalies",
            phase=1,
            description="Same passive listener, framed for noticing a MAC that keeps changing its "
            "claimed IP (or vice versa) — a signal worth investigating, without this tool itself doing "
            "anything active about it.",
            risk="quiet",
            template="arpwatch -i {iface} -f {output}/arpwatch_flipflop_{iface}.log -d",
            needs=("iface", "output"),
            notes="-d keeps arpwatch in the foreground with debug output for live review in-lab.",
        ),
    ),
    # ------------------------------------------------------------------
    # netcat — listeners, connects, transfers, quiet scanning
    # ------------------------------------------------------------------
    "netcat": (
        Action(
            id="netcat.banner_grab",
            label="Banner grab",
            phase=5,
            description="Connects to a service port and prints whatever banner/greeting it sends back — "
            "a quick, read-only way to fingerprint what's listening.",
            risk="quiet",
            template="nc -nv {target} {port}",
            needs=("target", "port"),
        ),
        Action(
            id="netcat.file_receive",
            label="Receive a file (listener side)",
            phase=6,
            description="Listens on a port and writes whatever stream it receives straight to a file — "
            "pair with netcat.file_send_pair below run on the sending in-scope host.",
            risk="normal",
            template="nc -lvnp {port} > {file}",
            needs=("port", "file"),
            notes="Lab-scope only: run the receiver on a host you control, and only accept transfers "
            "from other authorized in-scope hosts.",
        ),
        Action(
            id="netcat.file_send_pair",
            label="Send a file (sender side, pairs with file_receive)",
            phase=6,
            description="Streams a local file out to the listener started by netcat.file_receive on the "
            "other in-scope host. Run the receiver first.",
            risk="normal",
            template="nc -nv {target} {port} < {file}",
            needs=("target", "port", "file"),
            notes="Lab-scope only: destination must be an in-scope host you're authorized to move data to.",
        ),
        Action(
            id="netcat.port_scan_quiet",
            label="Simple TCP port scan (-zv)",
            phase=5,
            description="Zero-I/O connect scan across a port — netcat's lightweight stand-in for a full "
            "nmap scan when you just need a yes/no on a handful of ports.",
            risk="quiet",
            template="nc -zv {target} {port}",
            needs=("target", "port"),
        ),
        Action(
            id="netcat.listener_keep_open",
            label="Listener that stays open across connections (-k)",
            phase=6,
            description="Like the basic listener, but -k keeps it accepting new connections after one "
            "closes instead of exiting — useful for a pivot box that expects repeated check-ins.",
            risk="normal",
            template="nc -lvnpk {port} > {output}/nc_listener_{port}.log",
            needs=("port", "output"),
        ),
        Action(
            id="netcat.connect_udp",
            label="Connect over UDP (-u)",
            phase=5,
            description="Same connect as netcat.connect, but for UDP services — useful for banner/probe "
            "checks against UDP-only in-scope services.",
            risk="quiet",
            template="nc -u {target} {port}",
            needs=("target", "port"),
        ),
        Action(
            id="netcat.shell_catch_note",
            label="Shell-catch listener (lab pivoting only)",
            phase=6,
            description="A plain listener (-lvnp) intended to catch an incoming connection from an "
            "in-scope host you already control — e.g. a lab exercise where a teammate's box calls back "
            "to you. This is a listener, not an exploit delivery mechanism.",
            risk="normal",
            template="nc -lvnp {port}",
            needs=("port",),
            notes="LAB SCOPE ONLY: only ever catch a callback that originates from a host you are "
            "authorized to pivot through in this exercise. Never point this at, or accept connections "
            "from, anything outside the authorized lab range.",
        ),
    ),
    # ------------------------------------------------------------------
    # socat — relays, port-forwards, file transfer, TTY-stable shells
    # ------------------------------------------------------------------
    "socat": (
        Action(
            id="socat.port_forward",
            label="TCP port forward to a second in-scope host",
            phase=6,
            description="Listens locally and forwards every connection on to a second in-scope host:port "
            "— a basic relay for reaching a box that isn't directly routable from where you're sitting.",
            risk="normal",
            template="socat TCP-LISTEN:{port},fork,reuseaddr TCP:{target}:{remote_port}",
            needs=("port", "target", "remote_port"),
            notes="Lab-scope only: both the listen side and {target} must be in-scope hosts for this "
            "exercise — this is a pivot relay, not a general-purpose proxy.",
        ),
        Action(
            id="socat.listen_exec_note",
            label="Listen-and-exec (note only — review carefully)",
            phase=6,
            description="Binds a listener that pipes whatever connects straight into a local command "
            "(EXEC:) instead of just relaying bytes — e.g. handing a caller an interactive shell on this "
            "box. Shown as a note for manual review before running, given how much more this does than a "
            "plain relay.",
            risk="normal",
            template="socat TCP-LISTEN:{port},fork,reuseaddr EXEC:/bin/bash",
            needs=("port",),
            notes="LAB SCOPE ONLY: review this command line-by-line before running. Only expose it to "
            "connections from in-scope hosts you are authorized to pivot through.",
        ),
        Action(
            id="socat.file_receive",
            label="File transfer — receiver side",
            phase=6,
            description="Listens on a port and writes the incoming stream to a file — socat's version of "
            "the netcat file-receive pattern, pairs with socat.file_send below.",
            risk="normal",
            template="socat TCP-LISTEN:{port},reuseaddr OPEN:{file},creat,append",
            needs=("port", "file"),
            notes="Lab-scope only: run on a host you control, accepting only from authorized in-scope hosts.",
        ),
        Action(
            id="socat.file_send",
            label="File transfer — sender side",
            phase=6,
            description="Opens a local file and streams it to a listener started by socat.file_receive "
            "on another in-scope host. Run the receiver first.",
            risk="normal",
            template="socat OPEN:{file} TCP:{target}:{remote_port}",
            needs=("file", "target", "remote_port"),
            notes="Lab-scope only: destination must be an in-scope host you're authorized to move data to.",
        ),
        Action(
            id="socat.tty_shell_catch",
            label="TTY-stable shell-catch listener (lab pivoting only)",
            phase=6,
            description="A listener that allocates a proper pty for whatever connects back, giving a "
            "stable, resizable terminal instead of a raw pipe — meant for catching a callback from an "
            "in-scope host you already control during a pivoting exercise.",
            risk="normal",
            template="socat FILE:`tty`,raw,echo=0 TCP-LISTEN:{port}",
            needs=("port",),
            notes="LAB SCOPE ONLY: only catch callbacks that originate from a host you are authorized to "
            "pivot through. Never aim this at anything outside the authorized lab range.",
        ),
        Action(
            id="socat.udp_relay",
            label="UDP relay between two in-scope hosts",
            phase=6,
            description="Same idea as the TCP port forward but for UDP traffic — relays UDP datagrams on "
            "a local port out to a second in-scope host:port.",
            risk="normal",
            template="socat UDP-LISTEN:{port},fork,reuseaddr UDP:{target}:{remote_port}",
            needs=("port", "target", "remote_port"),
        ),
        Action(
            id="socat.tls_relay",
            label="TLS-wrapped relay (OPENSSL)",
            phase=6,
            description="Wraps a relay in TLS using a cert/key pair so traffic between the two pivot "
            "legs isn't plaintext on the wire — useful when the exercise calls for an encrypted pivot "
            "channel instead of a bare TCP relay.",
            risk="normal",
            template="socat OPENSSL-LISTEN:{port},cert={file},verify=0,fork TCP:{target}:{remote_port}",
            needs=("port", "file", "target", "remote_port"),
            notes="Lab-scope only: {file} is a cert/key for the lab's own CA, not a real production cert.",
        ),
    ),
}
