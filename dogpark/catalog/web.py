"""Deep command catalog for the WEB group: nikto, gobuster, ffuf.

Operation DOGPARK is an authorized, isolated CSUSB cyberlab red-team class exercise.
This module is pure data — no network access, no subprocess execution — that feeds the
guided front-end's command-builder for standard Kali web-recon tools. Every action here
is recon / content-discovery / enumeration only: nothing destructive, no DoS/flood, no
aggressive auto-exploit chains.

See dogpark.tools for the Action dataclass and dogpark.catalog.__init__ for how
EXTRA_ACTIONS dicts (keyed by Tool.name) get folded into the base TOOLS registry.
"""

from __future__ import annotations

from dogpark.tools import Action

EXTRA_ACTIONS: dict[str, tuple[Action, ...]] = {
    # ------------------------------------------------------------------
    # nikto — web server scanner
    # ------------------------------------------------------------------
    "nikto": (
        Action(
            id="nikto.port",
            label="Scan a specific port",
            phase=3,
            description="Same basic scan but against a non-default port (e.g. a service found "
            "on 8080/8443 during port scanning) instead of the implied 80/443.",
            risk="normal",
            template="nikto -h {url} -p {port} -output {output}/nikto_{target}_{port}.txt",
            needs=("url", "target", "port", "output"),
        ),
        Action(
            id="nikto.ssl",
            label="Force SSL scan",
            phase=3,
            description="Forces nikto to talk SSL/TLS to the target, useful when a self-signed cert "
            "or port confuses auto-detection on an HTTPS service.",
            risk="normal",
            template="nikto -h {url} -ssl -output {output}/nikto_ssl_{target}.txt",
            needs=("url", "target", "output"),
        ),
        Action(
            id="nikto.tuning_interesting",
            label="Tuned scan — interesting files only",
            phase=3,
            description="Restricts the test set with -Tuning to interesting-file checks (category 9), "
            "a faster/narrower pass when you just want low-hanging backup files and configs.",
            risk="normal",
            template="nikto -h {url} -Tuning 9 -output {output}/nikto_tuning9_{target}.txt",
            needs=("url", "target", "output"),
            notes="Tuning codes: 1 file upload, 2 misconfig, 3 info disclosure, 4 XSS, 6 SQLi, 9 interesting files.",
        ),
        Action(
            id="nikto.tuning_full_minus_dos",
            label="Tuned scan — broad, skip known-slow checks",
            phase=3,
            description="Runs a broader set of nikto's test categories (misconfig, info disclosure, "
            "injection indicators) while explicitly excluding the slow/noisy denial-of-service "
            "test family (-Tuning x 7) to keep the run in scope for a recon-only exercise.",
            risk="normal",
            template="nikto -h {url} -Tuning 123489 -Tuning x 7 -output {output}/nikto_broad_{target}.txt",
            needs=("url", "target", "output"),
        ),
        Action(
            id="nikto.evasion",
            label="IDS evasion encoding",
            phase=3,
            description="Applies libwhisker evasion techniques (-evasion) to URL-encode/obfuscate "
            "requests so a signature-based IDS is less likely to flag the scan outright. Still a "
            "full enumeration pass, just encoded on the wire — use for the stealthier lane of the exercise.",
            risk="quiet",
            template="nikto -h {url} -evasion 1 -output {output}/nikto_evasion_{target}.txt",
            needs=("url", "target", "output"),
            notes="Evasion level 1 = random URI encoding (non-UTF8). Higher levels exist but degrade "
            "accuracy further; start at 1.",
        ),
        Action(
            id="nikto.auth_basic",
            label="Authenticated scan (HTTP Basic)",
            phase=3,
            description="Supplies HTTP Basic credentials (-id user:pass) so nikto can enumerate paths "
            "that sit behind a login prompt instead of just bouncing off 401s.",
            risk="normal",
            template="nikto -h {url} -id {username}:{password} -output {output}/nikto_auth_{target}.txt",
            needs=("url", "target", "username", "password", "output"),
        ),
        Action(
            id="nikto.via_proxy",
            label="Scan through a pivot/proxy",
            phase=4,
            description="Routes the scan through an upstream HTTP proxy (-useproxy), e.g. a SOCKS-to-HTTP "
            "bridge on a pivot box, for reaching a web service only visible from a compromised host deeper "
            "in scope. Set the proxy in nikto's config or pass a proxy host:port here.",
            risk="normal",
            template="nikto -h {url} -useproxy {proxy} -output {output}/nikto_pivot_{target}.txt",
            needs=("url", "target", "proxy", "output"),
            notes="For SOCKS pivots, pair with proxychains: proxychains nikto -h {url} ... — adjust the "
            "command manually if proxychains is the active pivot method.",
        ),
        Action(
            id="nikto.save_csv",
            label="Save results as CSV",
            phase=3,
            description="Same basic scan but writes machine-readable CSV (-Format csv) instead of plain "
            "text, handy for feeding findings into a spreadsheet or report template.",
            risk="normal",
            template="nikto -h {url} -o {output}/nikto_{target}.csv -Format csv",
            needs=("url", "target", "output"),
        ),
    ),
    # ------------------------------------------------------------------
    # gobuster — directory / dns / vhost brute forcer
    # ------------------------------------------------------------------
    "gobuster": (
        Action(
            id="gobuster.dir_common",
            label="Directory brute force — common wordlist",
            phase=3,
            description="Fast first pass against the small dirb 'common.txt' list — good starting point "
            "before committing to a bigger, slower wordlist.",
            risk="normal",
            template="gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt "
            "-o {output}/gobuster_dir_common_{target}.txt",
            needs=("url", "output", "target"),
        ),
        Action(
            id="gobuster.dir_big",
            label="Directory brute force — big wordlist",
            phase=3,
            description="Deeper pass with SecLists' raft-medium-directories list once the common list is "
            "exhausted and more coverage is wanted.",
            risk="normal",
            template="gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt "
            "-o {output}/gobuster_dir_big_{target}.txt",
            needs=("url", "output", "target"),
        ),
        Action(
            id="gobuster.dir_extensions",
            label="Directory brute force with file extensions",
            phase=3,
            description="Adds -x to also try common backend extensions (php,txt,bak,asp,aspx) appended "
            "to each wordlist entry, catching loose backup/source files a bare dir scan misses.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -x php,txt,bak,asp,aspx "
            "-o {output}/gobuster_dir_ext_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dir_status_filter",
            label="Directory brute force — filter status codes",
            phase=3,
            description="Uses -sc to only report specific status codes (200,204,301,302,307,403), cutting "
            "noise from a chatty catch-all 200 or wildcard response.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -sc 200,204,301,302,307,403 "
            "-o {output}/gobuster_dir_filtered_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dir_loud_threads",
            label="Directory brute force — high concurrency",
            phase=3,
            description="Cranks threads (-t 50) for a fast, loud pass. Generates a lot of requests per "
            "second — expect it to be noticeable to any monitoring on the target.",
            risk="loud",
            template="gobuster dir -u {url} -w {wordlist} -t 50 -o {output}/gobuster_dir_fast_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dir_quiet_delay",
            label="Directory brute force — low concurrency + delay",
            phase=3,
            description="Drops to a single thread (-t 1) with a per-request --delay to stay under "
            "rate-based detection, trading speed for stealth.",
            risk="quiet",
            template="gobuster dir -u {url} -w {wordlist} -t 1 --delay 500ms "
            "-o {output}/gobuster_dir_slow_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dns_subdomains",
            label="DNS subdomain brute force",
            phase=3,
            description="Switches to gobuster's dns mode to brute-force subdomains of the target domain "
            "against a wordlist, surfacing dev/staging/admin hosts not linked from the main site.",
            risk="normal",
            template="gobuster dns -d {host} -w {wordlist} -o {output}/gobuster_dns_{host}.txt",
            needs=("host", "wordlist", "output"),
        ),
        Action(
            id="gobuster.vhost_append",
            label="Virtual host brute force — append domain",
            phase=3,
            description="vhost mode with --append-domain, trying each wordlist word as a Host-header "
            "subdomain of the base domain (e.g. admin.target.lab) to find vhosts sharing one IP.",
            risk="normal",
            template="gobuster vhost -u {url} -w {wordlist} --append-domain "
            "-o {output}/gobuster_vhost_append_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dir_pattern",
            label="Directory brute force with pattern file",
            phase=3,
            description="Uses -p to apply a pattern file that expands each wordlist word into several "
            "variants (e.g. {{GOBUSTER}}.bak, {{GOBUSTER}}.old), widening coverage for backup-file hunting.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -p {pattern} -o {output}/gobuster_dir_pattern_{target}.txt",
            needs=("url", "wordlist", "pattern", "output", "target"),
        ),
        Action(
            id="gobuster.dir_follow_redirect",
            label="Directory brute force — follow redirects",
            phase=3,
            description="Adds -r so gobuster follows 3xx redirects instead of just logging them, useful "
            "on sites that bounce every unauthenticated path to a login page.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -r -o {output}/gobuster_dir_redir_{target}.txt",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="gobuster.dir_authenticated_cookie",
            label="Authenticated directory brute force (cookie)",
            phase=3,
            description="Passes a session cookie with -c so the scan runs as a logged-in user, surfacing "
            "authenticated-only paths that a pre-auth scan can't reach.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -c {cookie} -o {output}/gobuster_dir_auth_{target}.txt",
            needs=("url", "wordlist", "cookie", "output", "target"),
        ),
        Action(
            id="gobuster.dir_authenticated_header",
            label="Authenticated directory brute force (header)",
            phase=3,
            description="Passes a custom auth header with -H (e.g. an API bearer token or session header) "
            "for authenticated fuzzing against APIs that don't use cookies.",
            risk="normal",
            template="gobuster dir -u {url} -w {wordlist} -H {header} -o {output}/gobuster_dir_authhdr_{target}.txt",
            needs=("url", "wordlist", "header", "output", "target"),
        ),
    ),
    # ------------------------------------------------------------------
    # ffuf — fast web fuzzer
    # ------------------------------------------------------------------
    "ffuf": (
        Action(
            id="ffuf.dir_common",
            label="Directory fuzz — common wordlist",
            phase=3,
            description="Baseline directory fuzz against dirb's common.txt, FUZZ in the path, a quick "
            "first look before going deeper.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt "
            "-o {output}/ffuf_dir_common_{target}.json -of json",
            needs=("url", "output", "target"),
        ),
        Action(
            id="ffuf.dir_recursive",
            label="Directory fuzz — recursive",
            phase=3,
            description="Adds -recursion -recursion-depth 2 so ffuf automatically re-fuzzes any "
            "directory it finds, mapping nested structure without manually re-running per subfolder.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -recursion -recursion-depth 2 "
            "-o {output}/ffuf_dir_recursive_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.extension_fuzz",
            label="File extension fuzz",
            phase=3,
            description="Fuzzes with -e appending common extensions (.php,.bak,.txt,.zip) to each "
            "wordlist entry, hunting for stray source/backup files on a known path.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -e .php,.bak,.txt,.zip "
            "-o {output}/ffuf_ext_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.vhost_fuzz",
            label="Virtual host fuzz (Host header)",
            phase=3,
            description="Fuzzes the Host header (-H 'Host: FUZZ.{host}') against the IP instead of the "
            "URL path, discovering additional vhosts served off the same listener.",
            risk="normal",
            template="ffuf -u {url} -H 'Host: FUZZ.{host}' -w {wordlist} "
            "-o {output}/ffuf_vhost_{target}.json -of json",
            needs=("url", "host", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.param_get",
            label="GET parameter fuzz",
            phase=3,
            description="Fuzzes a GET query parameter's name or value (?FUZZ=test or ?id=FUZZ) to find "
            "hidden/undocumented parameters a web app responds differently to.",
            risk="normal",
            template="ffuf -u '{url}?FUZZ=test' -w {wordlist} -o {output}/ffuf_param_get_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.param_post",
            label="POST body parameter fuzz",
            phase=3,
            description="Fuzzes a POST body field via -d with FUZZ in the payload and the right "
            "Content-Type header, for discovering hidden form/API parameters on write endpoints.",
            risk="normal",
            template="ffuf -u {url} -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' "
            "-w {wordlist} -o {output}/ffuf_param_post_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.clusterbomb_multi_wordlist",
            label="Clusterbomb fuzz — two wordlists",
            phase=3,
            description="Uses two FUZZ keywords (W1/W2) with -mode clusterbomb to try every combination "
            "of a username wordlist and a path/parameter wordlist in one run, e.g. per-user hidden paths.",
            risk="normal",
            template="ffuf -u {url}/W1FUZZ/W2FUZZ -w {wordlist}:W1FUZZ -w {wordlist2}:W2FUZZ -mode clusterbomb "
            "-o {output}/ffuf_clusterbomb_{target}.json -of json",
            needs=("url", "wordlist", "wordlist2", "output", "target"),
        ),
        Action(
            id="ffuf.matchers_status",
            label="Fuzz with status-code matcher",
            phase=3,
            description="Uses -mc to only match specific response codes (200,301,302,403), the usual "
            "first filter to cut irrelevant noise out of a big wordlist run.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 "
            "-o {output}/ffuf_mc_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.filters_size_words",
            label="Fuzz with size/word filters",
            phase=3,
            description="Uses -fs/-fw to filter out responses of a known boilerplate size or word count "
            "(e.g. a soft-404 page), the standard way to silence a wildcard response during calibration.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -fs {filter_size} -fw {filter_words} "
            "-o {output}/ffuf_filtered_{target}.json -of json",
            needs=("url", "wordlist", "filter_size", "filter_words", "output", "target"),
        ),
        Action(
            id="ffuf.filters_fc",
            label="Fuzz with status-code filter",
            phase=3,
            description="Uses -fc to filter out a specific status code (e.g. 404) instead of allow-listing "
            "codes with -mc — useful when the app doesn't answer 404 cleanly and you want everything else.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -fc 404 -o {output}/ffuf_fc_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.rate_limited_quiet",
            label="Rate-limited fuzz (quiet)",
            phase=3,
            description="Caps requests per second with -rate and adds -p (inter-request delay range) to "
            "spread the run out thin, trading speed for a lower chance of tripping rate-based alerting.",
            risk="quiet",
            template="ffuf -u {url}/FUZZ -w {wordlist} -rate 5 -p 0.5-1.5 "
            "-o {output}/ffuf_quiet_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.high_thread_loud",
            label="High-thread fuzz (loud)",
            phase=3,
            description="Raises worker threads with -t 100 and no delay for maximum throughput — fast but "
            "unmistakably loud on the wire, intended for the exercise's noisy/overt lane.",
            risk="loud",
            template="ffuf -u {url}/FUZZ -w {wordlist} -t 100 -o {output}/ffuf_fast_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
        Action(
            id="ffuf.auth_header_cookie",
            label="Authenticated fuzz (header/cookie)",
            phase=3,
            description="Adds a custom header, e.g. -H 'Cookie: {cookie}' or an Authorization bearer "
            "token, so the fuzz runs in an authenticated session and reaches logged-in-only content.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -H 'Cookie: {cookie}' "
            "-o {output}/ffuf_auth_{target}.json -of json",
            needs=("url", "wordlist", "cookie", "output", "target"),
        ),
        Action(
            id="ffuf.json_output_only",
            label="Fuzz with structured JSON output",
            phase=3,
            description="Plain directory fuzz with explicit -of json (and no console colorizing concerns) "
            "so results feed cleanly into another script or the report template.",
            risk="normal",
            template="ffuf -u {url}/FUZZ -w {wordlist} -o {output}/ffuf_results_{target}.json -of json",
            needs=("url", "wordlist", "output", "target"),
        ),
    ),
}
