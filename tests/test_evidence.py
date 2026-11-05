"""Evidence helper tests: findings store, redaction, script command, screenshot reminder."""

from dogpark import evidence


def test_script_command_builds_expected_string():
    cmd = evidence.script_command("/tmp/dogpark", 3)
    assert cmd == "script -a /tmp/dogpark/session/day3_terminal.log"


def test_redact_masks_password_kv():
    text = "login ok, password=SuperSecret1 for user admin"
    redacted = evidence.redact(text)
    assert "SuperSecret1" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_masks_ntlm_hash_pair():
    text = "admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"
    redacted = evidence.redact(text)
    assert "aad3b435b51404eeaad3b435b51404ee" not in redacted


def test_redact_empty_text():
    assert evidence.redact("") == ""


def test_screenshot_reminder_mentions_action():
    reminder = evidence.screenshot_reminder("nmap full scan")
    assert "nmap full scan" in reminder


def test_findings_store_add_and_all(tmp_path):
    store = evidence.FindingsStore(str(tmp_path))
    finding = store.add(
        target="192.168.1.10",
        severity="Medium",
        title="Outdated web server banner",
        impact="Information disclosure",
        remediation="Patch web server",
    )
    assert finding.id == "F001"
    all_findings = store.all()
    assert len(all_findings) == 1
    assert all_findings[0].title == "Outdated web server banner"


def test_findings_store_invalid_severity_defaults_to_info(tmp_path):
    store = evidence.FindingsStore(str(tmp_path))
    finding = store.add(target="x", severity="Nonsense", title="t")
    assert finding.severity == "Info"


def test_time_to_compromise_tracker(tmp_path):
    tracker = evidence.TimeToCompromiseTracker(str(tmp_path))
    tracker.mark("dc01", "first_contact")
    tracker.mark("dc01", "domain_admin")
    records = tracker.all()
    assert len(records) == 2
    assert records[1]["event"] == "domain_admin"
