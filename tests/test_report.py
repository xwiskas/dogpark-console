"""Report generation + template rendering tests. Pure data in, string out — no live tools,
no network. The I/O wrapper (`report.generate`) is exercised against a tmp_path fixture."""

import json

from dogpark import report
from dogpark.evidence import Finding


SAMPLE_RECORDS = [
    {
        "timestamp": "2026-11-05T10:00:00+00:00",
        "target": "192.168.1.10",
        "action_id": "nmap.quiet_top_ports",
        "command": "nmap -T2 -sS 192.168.1.10 -p 1-1000",
        "exit_code": 0,
        "log_path": "/tmp/dogpark/runs/run1.log",
    },
]

SAMPLE_FINDINGS = [
    Finding(
        id="F001",
        time="2026-11-05T10:05:00+00:00",
        target="192.168.1.10",
        severity="High",
        title="Null-session SMB enumeration allowed",
        evidence_path="/tmp/dogpark/runs/enum.log",
        impact="Anonymous users can enumerate shares and users.",
        remediation="Disable null sessions; restrict anonymous SMB access.",
    ),
    Finding(
        id="F002",
        time="2026-11-05T11:00:00+00:00",
        target="192.168.1.20",
        severity="Critical",
        title="Domain Admin credential reuse",
        evidence_path="",
        impact="password=Summer2024! reused across hosts",
        remediation="Rotate credentials; enforce unique local admin passwords.",
    ),
]


def test_severity_counts():
    counts = report.severity_counts(SAMPLE_FINDINGS)
    assert counts["Critical"] == 1
    assert counts["High"] == 1
    assert counts["Medium"] == 0


def test_render_findings_table_contains_counts():
    table = report.render_findings_table(SAMPLE_FINDINGS)
    assert "| Critical | 1 |" in table
    assert "| High | 1 |" in table


def test_render_detailed_findings_redacts_password():
    detail = report.render_detailed_findings(SAMPLE_FINDINGS)
    assert "Summer2024!" not in detail
    assert "[REDACTED]" in detail


def test_render_attack_narrative_includes_records():
    narrative = report.render_attack_narrative(SAMPLE_RECORDS)
    assert "nmap.quiet_top_ports" in narrative
    assert "192.168.1.10" in narrative


def test_render_attack_narrative_empty():
    assert "No tool runs" in report.render_attack_narrative([])


def test_render_remediation_matrix_orders_by_severity():
    matrix = report.render_remediation_matrix(SAMPLE_FINDINGS)
    critical_idx = matrix.index("Critical")
    high_idx = matrix.index("High")
    assert critical_idx < high_idx


def test_render_engagement_header_redacts_creds():
    engagement = {
        "domain": "DOGPARK.LOCAL",
        "dc_ip": "192.168.1.1",
        "domain_admin": True,
        "da_method": "secretsdump",
        "machine_inventory": {"domain_controller": "192.168.1.1"},
        "creds_harvested": ["admin:password=hunter2"],
        "time_to_da": "4h12m",
    }
    header = report.render_engagement_header(engagement)
    assert "DOGPARK.LOCAL" in header
    assert "Yes" in header
    assert "hunter2" not in header


def test_render_report_markdown_full_document():
    md = report.render_report_markdown(SAMPLE_RECORDS, SAMPLE_FINDINGS, ["/tmp/dogpark/runs/run1.log"])
    assert "# Operation DOGPARK" in md
    assert "Executive Summary" in md
    assert "Findings Table" in md
    assert "Detailed Findings" in md
    assert "Attack Path" in md
    assert "Remediation Priority Matrix" in md
    assert "Appendices" in md
    assert "Summer2024!" not in md  # redaction holds through full-document render


def test_generate_writes_expected_files(tmp_path):
    output_dir = tmp_path / "dogpark"
    session_dir = output_dir / "session"
    session_dir.mkdir(parents=True)
    with open(session_dir / "day1.jsonl", "w", encoding="utf-8") as f:
        for record in SAMPLE_RECORDS:
            f.write(json.dumps(record) + "\n")

    findings_path = output_dir / "findings.jsonl"
    with open(findings_path, "w", encoding="utf-8") as f:
        for finding in SAMPLE_FINDINGS:
            f.write(json.dumps(finding.__dict__) + "\n")

    written = report.generate(str(output_dir))

    assert (output_dir / "report" / "appendix_n_report.md").exists()
    assert (output_dir / "report" / "appendix_n_report.txt").exists()
    assert (output_dir / "report" / "phase1_subscreen_summary.txt").exists()
    assert (output_dir / "report" / "phase2_dmz_summary.txt").exists()
    assert (output_dir / "report" / "phase3_lan_summary.txt").exists()

    md_text = (output_dir / "report" / "appendix_n_report.md").read_text(encoding="utf-8")
    assert "nmap.quiet_top_ports" in md_text
    assert written["report_md"].endswith("appendix_n_report.md")
