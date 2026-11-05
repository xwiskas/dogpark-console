"""Deep command catalog for the CREDENTIALS group — hydra (online login testing) plus
john and hashcat (offline hash cracking).

Pure data module: no subprocess calls, no network access, no filesystem access beyond
nothing. Every Action here only builds a string template for the GUI to show the student
for manual review before they copy/paste and run it themselves on their own Kali VM.

hydra targets in-scope lab services only and is risk="normal"/"loud" because it sends
live login attempts over the network. Every hydra action carries a lockout/authorization
note — Operation DOGPARK is an authorized, isolated university cyberlab exercise, but
account-lockout policies still apply to the lab's own directory/services, and hammering
them is both bad tradecraft and can break the exercise for the whole class.

john and hashcat are entirely offline (cracking a hash file already in hand — e.g. pulled
via secretsdump or Responder in an earlier phase) and are marked risk="quiet" since they
generate zero network traffic.
"""

from __future__ import annotations

from dogpark.tools import Action

_LOCKOUT_NOTE = (
    "Online attack against a live lab service — check the lab's account-lockout policy "
    "before running. Keep -t low and consider -W to space out attempts. Stop immediately "
    "if you see lockout indicators. Only against in-scope DOGPARK targets you're authorized "
    "to test."
)

EXTRA_ACTIONS: dict[str, tuple[Action, ...]] = {
    "hydra": (
        Action(
            id="hydra.single_user_wordlist",
            label="Single user + wordlist",
            phase=4,
            description="Tries one known username against a password wordlist over a chosen service module. "
            "Good first pass when you already have a valid username from enumeration.",
            risk="normal",
            template="hydra -l {user} -P {wordlist} -t 4 -W 2 {service}://{target}",
            needs=("user", "wordlist", "service", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.userlist_wordlist",
            label="Userlist + wordlist",
            phase=4,
            description="Tries a list of usernames against a password wordlist (full L x P sweep) over a "
            "chosen service module. Much noisier than a single-user run — expect many attempts.",
            risk="loud",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 {service}://{target}",
            needs=("userlist", "wordlist", "service", "target"),
            notes=_LOCKOUT_NOTE + " A full userlist x wordlist sweep multiplies attempt count — consider "
            "a smaller wordlist or -f to stop on first hit.",
        ),
        Action(
            id="hydra.ssh_module",
            label="SSH login test",
            phase=4,
            description="Password-sprays SSH (service module 'ssh') with a userlist and wordlist, "
            "conservative task count.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 ssh://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.ftp_module",
            label="FTP login test",
            phase=4,
            description="Password-sprays FTP (service module 'ftp') with a userlist and wordlist.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 ftp://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.smb_module",
            label="SMB login test",
            phase=4,
            description="Password-sprays SMB (service module 'smb') with a userlist and wordlist — useful "
            "for testing weak domain/local creds against a Windows/Samba host.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 smb://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE + " SMB lockout policies on AD domains are usually stricter than local "
            "accounts — be extra conservative here.",
        ),
        Action(
            id="hydra.rdp_module",
            label="RDP login test",
            phase=4,
            description="Password-sprays RDP (service module 'rdp') with a userlist and wordlist. RDP auth "
            "is slow per-attempt, so keep -t very low.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 2 -W 4 rdp://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE + " RDP is slow and prone to tripping Windows lockout fast — this template "
            "intentionally uses -t 2 -W 4.",
        ),
        Action(
            id="hydra.http_get_basic",
            label="HTTP GET (basic auth) login test",
            phase=4,
            description="Password-sprays an HTTP endpoint protected by HTTP Basic auth via the http-get "
            "module.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 {target} http-get {url_path}",
            needs=("userlist", "wordlist", "target", "url_path"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.http_post_form",
            label="HTTP POST form login test",
            phase=4,
            description="Tries credentials against an HTML login form via http-post-form. The form string "
            "needs the POST path, field names, and a failure-string marker "
            "(e.g. '/login:user=^USER^&pass=^PASS^:F=invalid').",
            risk="normal",
            template='hydra -L {userlist} -P {wordlist} -t 4 {target} http-post-form "{form}"',
            needs=("userlist", "wordlist", "target", "form"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.mysql_module",
            label="MySQL login test",
            phase=5,
            description="Password-sprays a MySQL service (service module 'mysql') with a userlist and "
            "wordlist.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 mysql://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.mssql_module",
            label="MSSQL login test",
            phase=5,
            description="Password-sprays a Microsoft SQL Server (service module 'mssql') with a userlist "
            "and wordlist.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 mssql://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.postgres_module",
            label="PostgreSQL login test",
            phase=5,
            description="Password-sprays PostgreSQL (service module 'postgres') with a userlist and "
            "wordlist.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 postgres://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.telnet_module",
            label="Telnet login test",
            phase=4,
            description="Password-sprays Telnet (service module 'telnet') with a userlist and wordlist.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 telnet://{target}",
            needs=("userlist", "wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.vnc_module",
            label="VNC login test",
            phase=4,
            description="Password-sprays VNC (service module 'vnc') with a wordlist. VNC has no separate "
            "username field — only a password prompt.",
            risk="normal",
            template="hydra -P {wordlist} -t 4 -W 2 vnc://{target}",
            needs=("wordlist", "target"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.custom_port",
            label="Service test on a custom port",
            phase=4,
            description="Same as a normal service-module run but against a non-default port (e.g. an SSH "
            "daemon moved off 22).",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 -s {port} {service}://{target}",
            needs=("userlist", "wordlist", "service", "target", "port"),
            notes=_LOCKOUT_NOTE,
        ),
        Action(
            id="hydra.quiet_low_tasks",
            label="Quiet run — low -t, generous -W",
            phase=4,
            description="Lockout-aware conservative preset: -t 2 and -W 5 to minimize attempts-per-minute "
            "against a service with a tight lockout threshold.",
            risk="quiet",
            template="hydra -L {userlist} -P {wordlist} -t 2 -W 5 {service}://{target}",
            needs=("userlist", "wordlist", "service", "target"),
            notes=_LOCKOUT_NOTE + " This preset is the conservative default — use it unless you've "
            "confirmed the service tolerates a faster rate.",
        ),
        Action(
            id="hydra.loud_fast_tasks",
            label="Fast run — high -t",
            phase=5,
            description="Faster preset (-t 16) for a service confirmed to have no meaningful lockout "
            "policy, or when speed matters more than stealth in this phase.",
            risk="loud",
            template="hydra -L {userlist} -P {wordlist} -t 16 {service}://{target}",
            needs=("userlist", "wordlist", "service", "target"),
            notes=_LOCKOUT_NOTE + " Only use this faster preset after confirming the target service's "
            "lockout policy tolerates it — defaults to the quiet preset otherwise.",
        ),
        Action(
            id="hydra.stop_on_first",
            label="Stop on first valid credential (-f)",
            phase=4,
            description="Same as a standard sweep but exits immediately once one valid login is found, "
            "minimizing further noise/attempts.",
            risk="normal",
            template="hydra -L {userlist} -P {wordlist} -t 4 -W 2 -f {service}://{target}",
            needs=("userlist", "wordlist", "service", "target"),
            notes=_LOCKOUT_NOTE + " -f is the recommended default for any live sweep — no reason to keep "
            "trying after a hit.",
        ),
        Action(
            id="hydra.resume_session",
            label="Resume a saved session",
            phase=4,
            description="Resumes a previously interrupted hydra run from its restore file (hydra writes "
            "hydra.restore automatically when a run is stopped).",
            risk="normal",
            template="hydra -R",
            needs=(),
            notes=_LOCKOUT_NOTE + " Resuming continues whatever attempt budget the original run was "
            "using — re-check lockout state before resuming.",
        ),
    ),
    "john": (
        Action(
            id="john.rockyou_wordlist",
            label="Wordlist crack with rockyou",
            phase=5,
            description="Runs john against a hash file using the stock rockyou.txt wordlist. Fully "
            "offline — no network traffic.",
            risk="quiet",
            template="john --wordlist=/usr/share/wordlists/rockyou.txt {hashfile}",
            needs=("hashfile",),
        ),
        Action(
            id="john.wordlist_with_rules",
            label="Wordlist crack with mangling rules",
            phase=5,
            description="Runs a wordlist through john's rule engine (case/leet/append-digit mangles) for "
            "much better coverage than the raw wordlist alone.",
            risk="quiet",
            template="john --wordlist={wordlist} --rules {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.incremental",
            label="Incremental (brute-force) mode",
            phase=6,
            description="John's built-in Markov-based brute-force mode — no wordlist needed, tries "
            "character combinations ordered by likelihood. Slow but exhaustive for short passwords.",
            risk="quiet",
            template="john --incremental {hashfile}",
            needs=("hashfile",),
        ),
        Action(
            id="john.format_ntlm",
            label="NTLM hash crack (--format=NT)",
            phase=5,
            description="Cracks Windows NT/NTLM hashes (e.g. from a SAM/NTDS dump) with a specific format "
            "forced so john doesn't have to guess the hash type.",
            risk="quiet",
            template="john --format=NT --wordlist={wordlist} {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.format_netntlmv2",
            label="net-NTLMv2 crack (--format=netntlmv2)",
            phase=5,
            description="Cracks net-NTLMv2 challenge/response hashes captured from the wire (e.g. via "
            "Responder) rather than SAM/NTDS dumps.",
            risk="quiet",
            template="john --format=netntlmv2 --wordlist={wordlist} {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.format_sha512crypt",
            label="sha512crypt crack (Linux /etc/shadow)",
            phase=5,
            description="Cracks Linux sha512crypt hashes pulled from /etc/shadow, with the format forced "
            "explicitly.",
            risk="quiet",
            template="john --format=sha512crypt --wordlist={wordlist} {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.format_md5crypt",
            label="md5crypt crack (legacy Linux/Apache)",
            phase=5,
            description="Cracks legacy md5crypt hashes (older /etc/shadow entries or Apache htpasswd "
            "files).",
            risk="quiet",
            template="john --format=md5crypt --wordlist={wordlist} {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.format_krb5",
            label="Kerberos ticket crack (--format=krb5tgs)",
            phase=5,
            description="Cracks a Kerberoasted TGS ticket (krb5tgs format) pulled earlier via "
            "impacket-GetUserSPNs, recovering the service account's plaintext password offline.",
            risk="quiet",
            template="john --format=krb5tgs --wordlist={wordlist} {hashfile}",
            needs=("wordlist", "hashfile"),
        ),
        Action(
            id="john.mask_mode",
            label="Mask-based crack",
            phase=6,
            description="Targeted brute force using a mask pattern (e.g. '?u?l?l?l?l?d?d' for an "
            "Uppercase+4 lowercase+2 digits pattern) when you know the org's password policy shape.",
            risk="quiet",
            template="john --mask={mask} {hashfile}",
            needs=("mask", "hashfile"),
        ),
        Action(
            id="john.show_cracked",
            label="Show cracked results",
            phase=5,
            description="Prints previously-cracked plaintext results stored in john's local potfile for "
            "this hash file.",
            risk="quiet",
            template="john --show {hashfile}",
            needs=("hashfile",),
        ),
        Action(
            id="john.session_restore",
            label="Named session + restore",
            phase=6,
            description="Runs a long crack under a named session so it can be paused and resumed later "
            "with --restore=<session> instead of restarting from zero.",
            risk="quiet",
            template="john --session={session} --wordlist={wordlist} {hashfile}",
            needs=("session", "wordlist", "hashfile"),
        ),
    ),
    "hashcat": (
        Action(
            id="hashcat.straight_wordlist",
            label="Straight wordlist attack (-a 0)",
            phase=5,
            description="Standard dictionary attack: tries every word in the wordlist as-is against the "
            "hash file for the given hash mode.",
            risk="quiet",
            template="hashcat -a 0 -m {hash_mode} {hashfile} {wordlist} -o {output}",
            needs=("hash_mode", "hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.wordlist_rules_best64",
            label="Wordlist + best64 rules",
            phase=5,
            description="Dictionary attack with the bundled best64.rule rule set applied to each word "
            "(case flips, appends, leet subs) for much higher coverage per-word.",
            risk="quiet",
            template="hashcat -a 0 -m {hash_mode} -r {rules} {hashfile} {wordlist} -o {output}",
            needs=("hash_mode", "rules", "hashfile", "wordlist", "output"),
            notes="Example rules path: /usr/share/hashcat/rules/best64.rule",
        ),
        Action(
            id="hashcat.wordlist_rules_d3ad0ne",
            label="Wordlist + d3ad0ne rules",
            phase=5,
            description="Dictionary attack using the larger, slower d3ad0ne.rule set for deeper mangling "
            "coverage than best64.",
            risk="quiet",
            template="hashcat -a 0 -m {hash_mode} -r {rules} {hashfile} {wordlist} -o {output}",
            needs=("hash_mode", "rules", "hashfile", "wordlist", "output"),
            notes="Example rules path: /usr/share/hashcat/rules/d3ad0ne.rule — much slower than best64.",
        ),
        Action(
            id="hashcat.mask_brute",
            label="Mask/brute-force attack (-a 3)",
            phase=6,
            description="Pure brute force over a character-set mask — no wordlist needed. Example mask "
            "'?u?l?l?l?l?l?d?d' = Uppercase + 5 lowercase + 2 digits, a common enterprise policy shape.",
            risk="quiet",
            template="hashcat -a 3 -m {hash_mode} {hashfile} {mask} -o {output}",
            needs=("hash_mode", "hashfile", "mask", "output"),
            notes="Example masks: ?u?l?l?l?l?l?d?d (Capitalized+5+2 digits), ?d?d?d?d?d?d?d?d (8 digits, "
            "e.g. PINs), ?a?a?a?a?a?a (6-char full charset).",
        ),
        Action(
            id="hashcat.combinator",
            label="Combinator attack (-a 1)",
            phase=6,
            description="Concatenates every word from one wordlist with every word from a second wordlist "
            "(e.g. seasons + years) to generate compound-word candidates.",
            risk="quiet",
            template="hashcat -a 1 -m {hash_mode} {hashfile} {wordlist} {wordlist2} -o {output}",
            needs=("hash_mode", "hashfile", "wordlist", "wordlist2", "output"),
        ),
        Action(
            id="hashcat.mode_md5",
            label="MD5 crack (-m 0)",
            phase=5,
            description="Cracks raw MD5 hashes (hash mode 0) with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 0 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_sha1",
            label="SHA1 crack (-m 100)",
            phase=5,
            description="Cracks raw SHA1 hashes (hash mode 100) with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 100 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_ntlm",
            label="NTLM crack (-m 1000)",
            phase=5,
            description="Cracks Windows NTLM hashes (hash mode 1000) — the usual format for a SAM/NTDS "
            "dump — with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 1000 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_sha512crypt",
            label="sha512crypt crack (-m 1800)",
            phase=5,
            description="Cracks Linux sha512crypt hashes (hash mode 1800) from /etc/shadow with a "
            "wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 1800 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_netntlmv2",
            label="NetNTLMv2 crack (-m 5600)",
            phase=5,
            description="Cracks net-NTLMv2 challenge/response hashes (hash mode 5600) captured from the "
            "wire, e.g. via Responder, with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 5600 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_kerberoast",
            label="Kerberoast TGS crack (-m 13100)",
            phase=5,
            description="Cracks Kerberoasted TGS service tickets (hash mode 13100) pulled earlier via "
            "impacket-GetUserSPNs, with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 13100 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_asrep",
            label="AS-REP roast crack (-m 18200)",
            phase=5,
            description="Cracks AS-REP roasted hashes (hash mode 18200) from accounts with Kerberos "
            "pre-authentication disabled, with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 18200 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.mode_md5crypt",
            label="md5crypt crack (-m 500)",
            phase=5,
            description="Cracks legacy md5crypt hashes (hash mode 500) — older /etc/shadow entries or "
            "Apache htpasswd files — with a wordlist.",
            risk="quiet",
            template="hashcat -a 0 -m 500 {hashfile} {wordlist} -o {output}",
            needs=("hashfile", "wordlist", "output"),
        ),
        Action(
            id="hashcat.show_cracked",
            label="Show cracked results (--show)",
            phase=5,
            description="Prints previously-cracked plaintext:hash pairs from the potfile for this hash "
            "file without re-running the attack.",
            risk="quiet",
            template="hashcat -m {hash_mode} --show {hashfile}",
            needs=("hash_mode", "hashfile"),
        ),
        Action(
            id="hashcat.show_username",
            label="Show cracked results with usernames (--show --username)",
            phase=5,
            description="Same as --show but also prints the associated username when the hash file is in "
            "user:hash format — easier to map cracked passwords back to accounts.",
            risk="quiet",
            template="hashcat -m {hash_mode} --show --username {hashfile}",
            needs=("hash_mode", "hashfile"),
        ),
        Action(
            id="hashcat.workload_tuned",
            label="Workload-tuned run (-w)",
            phase=5,
            description="Runs a wordlist attack with an explicit workload profile (1=low to 4=nightmare) "
            "to control how hard hashcat leans on the GPU/CPU — useful on a shared or laptop VM.",
            risk="quiet",
            template="hashcat -a 0 -m {hash_mode} -w {workload} {hashfile} {wordlist} -o {output}",
            needs=("hash_mode", "workload", "hashfile", "wordlist", "output"),
            notes="Workload 1-2 is safer on a laptop/shared VM; 3-4 pushes the GPU harder.",
        ),
        Action(
            id="hashcat.potfile_disable",
            label="Run with potfile disabled (--potfile-disable)",
            phase=5,
            description="Runs a wordlist attack without reading/writing the potfile — useful for a clean "
            "re-run or when grading needs fresh-from-scratch cracking output.",
            risk="quiet",
            template="hashcat -a 0 -m {hash_mode} --potfile-disable {hashfile} {wordlist} -o {output}",
            needs=("hash_mode", "hashfile", "wordlist", "output"),
        ),
    ),
}
