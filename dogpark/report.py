"""Report generation — builds the Appendix N write-up from session logs + findings store.

Split into pure rendering functions (take plain data, return strings — unit-testable with
no live tools) and thin I/O wrappers that read the output dir and write the report files.
"""

from __future__ import annotations

import glob
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from dogpark.evidence import FindingsStore, Finding, redact

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")


# ---------------------------------------------------------------------------
# Data loading (I/O)
# ---------------------------------------------------------------------------

def load_session_records(output_dir: str) -> list[dict]:
    """Read every <output>/session/day*.jsonl file and return records sorted by timestamp."""
    session_dir = Path(output_dir).expanduser() / "session"
    records: list[dict] = []
    if not session_dir.exists():
        return records
    for path in sorted(session_dir.glob("day*.jsonl")):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    records.sort(key=lambda r: r.get("timestamp", ""))
    return records


def load_findings(output_dir: str) -> list[Finding]:
    return FindingsStore(output_dir).all()


def list_raw_logs(output_dir: str) -> list[str]:
    runs_dir = Path(output_dir).expanduser() / "runs"
    if not runs_dir.exists():
        return []
    return sorted(str(p) for p in runs_dir.glob("*.log"))


# ---------------------------------------------------------------------------
# Pure rendering helpers
# ---------------------------------------------------------------------------

def severity_counts(findings: list[Finding]) -> dict:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity if f.severity in counts else "Info"] += 1
    return counts


def render_findings_table(findings: list[Finding]) -> str:
    counts = severity_counts(findings)
    lines = ["| Severity | Count |", "|---|---|"]
    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev} | {counts[sev]} |")
    return "\n".join(lines)


def render_detailed_findings(findings: list[Finding]) -> str:
    if not findings:
        return "_No findings recorded yet._"
    blocks = []
    for f in findings:
        blocks.append(
            f"### {f.id} — {f.title} ({f.severity})\n\n"
            f"- **Target:** {f.target}\n"
            f"- **Time:** {f.time}\n"
            f"- **Evidence:** {f.evidence_path or '_none attached_'}\n"
            f"- **Impact:** {redact(f.impact) or '_not described_'}\n"
            f"- **Remediation:** {redact(f.remediation) or '_not described_'}\n"
        )
    return "\n".join(blocks)


def render_attack_narrative(records: list[dict]) -> str:
    if not records:
        return "_No tool runs recorded yet._"
    lines = []
    for r in records:
        ts = r.get("timestamp", "?")
        target = r.get("target", "?")
        action_id = r.get("action_id", "?")
        exit_code = r.get("exit_code")
        command = redact(r.get("command", ""))
        status = "ok" if exit_code == 0 else f"exit={exit_code}"
        lines.append(f"- `{ts}` — **{action_id}** against `{target}` ({status}): `{command}`")
    return "\n".join(lines)


def render_appendices(raw_logs: list[str]) -> str:
    if not raw_logs:
        return "_No raw scan logs recorded yet._"
    return "\n".join(f"- `{p}`" for p in raw_logs)


def render_remediation_matrix(findings: list[Finding]) -> str:
    """Findings ordered Critical -> Info as a simple remediation priority matrix."""
    if not findings:
        return "_No findings to prioritize yet._"
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 99)
    lines = ["| Priority | Finding | Severity | Target |", "|---|---|---|---|"]
    for i, f in enumerate(ordered, start=1):
        lines.append(f"| {i} | {f.title} | {f.severity} | {f.target} |")
    return "\n".join(lines)


def render_engagement_header(engagement: Optional[dict]) -> str:
    engagement = engagement or {}
    domain = engagement.get("domain", "")
    dc_ip = engagement.get("dc_ip", "")
    domain_admin = engagement.get("domain_admin", False)
    da_method = engagement.get("da_method", "")
    machine_inventory = engagement.get("machine_inventory", {})
    creds_harvested = engagement.get("creds_harvested", [])
    time_to_da = engagement.get("time_to_da", "")

    lines = [
        f"- **Domain:** {domain or '_unknown_'}",
        f"- **Domain Controller IP:** {dc_ip or '_unknown_'}",
        f"- **Domain Admin obtained:** {'Yes' if domain_admin else 'No'}"
        + (f" (method: {da_method})" if domain_admin and da_method else ""),
        f"- **Time to Domain Admin:** {time_to_da or '_n/a_'}",
    ]
    if machine_inventory:
        lines.append("- **Machine inventory:**")
        for role, host in machine_inventory.items():
            lines.append(f"  - {role}: {host or '_unset_'}")
    if creds_harvested:
        lines.append("- **Credentials harvested (redacted):**")
        for cred in creds_harvested:
            lines.append(f"  - {redact(str(cred))}")
    return "\n".join(lines)


def render_report_markdown(
    records: list[dict],
    findings: list[Finding],
    raw_logs: list[str],
    engagement: Optional[dict] = None,
    generated_at: Optional[str] = None,
) -> str:
    generated_at = generated_at or datetime.now().isoformat()
    counts = severity_counts(findings)
    exec_summary = (
        f"This report covers {len(records)} recorded tool run(s) and {len(findings)} finding(s) "
        f"({counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium, "
        f"{counts['Low']} Low, {counts['Info']} Info) during Operation DOGPARK, an authorized "
        "CSUSB cyberlab exercise."
    )

    return f"""# Operation DOGPARK — Appendix N: Engagement Report

_Generated {generated_at}_

## Executive Summary

{exec_summary}

## Scope & Methodology

All activity in this report was performed against targets validated by the DOGPARK Console's
scope lock (RFC1918 lab ranges + the configured lab subnet only). Every command was reviewed
and run manually by the pentester; nothing in this engagement was auto-executed.

## Engagement Overview

{render_engagement_header(engagement)}

## Attack Narrative

{render_attack_narrative(records)}

## Findings Table

{render_findings_table(findings)}

## Detailed Findings

{render_detailed_findings(findings)}

## Attack Path (Initial Access -> Domain Admin)

{render_engagement_header(engagement)}

## Remediation Priority Matrix

{render_remediation_matrix(findings)}

## Appendices (Raw Scan Logs)

{render_appendices(raw_logs)}
"""


def render_phase_summary(phase_label: str, records: list[dict]) -> str:
    lines = [f"Operation DOGPARK — {phase_label} summary", ""]
    if not records:
        lines.append("No tool runs recorded for this phase.")
    else:
        for r in records:
            lines.append(
                f"{r.get('timestamp', '?')} | {r.get('target', '?')} | {r.get('action_id', '?')} | "
                f"exit={r.get('exit_code')}"
            )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# I/O wrapper — generates and writes all report files
# ---------------------------------------------------------------------------

def generate(output_dir: str, engagement: Optional[dict] = None) -> dict:
    """Generate the full report set under <output_dir>/report/ and return the paths written."""
    out = Path(output_dir).expanduser()
    report_dir = out / "report"
    report_dir.mkdir(parents=True, exist_ok=True)

    records = load_session_records(output_dir)
    findings = load_findings(output_dir)
    raw_logs = list_raw_logs(output_dir)

    md = render_report_markdown(records, findings, raw_logs, engagement=engagement)
    md_path = report_dir / "appendix_n_report.md"
    txt_path = report_dir / "appendix_n_report.txt"
    md_path.write_text(md, encoding="utf-8")
    txt_path.write_text(md, encoding="utf-8")  # same content, plain-text consumers just read it

    phase_files = {
        "phase1_subscreen_summary.txt": "Phase 1-2 Subscreen",
        "phase2_dmz_summary.txt": "Phase 3-5 DMZ",
        "phase3_lan_summary.txt": "Phase 6-7 LAN",
    }
    written = {"report_md": str(md_path), "report_txt": str(txt_path)}
    for filename, label in phase_files.items():
        content = render_phase_summary(label, records)
        path = report_dir / filename
        path.write_text(content, encoding="utf-8")
        written[filename] = str(path)

    return written
