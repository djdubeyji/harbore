"""
Context-aware payload generator — suggests targeted attack payloads
based on the finding type, technology stack, and endpoint context.
"""
import os
import json
import logging
from typing import Optional
from pydantic import BaseModel
import anthropic

log = logging.getLogger(__name__)

PAYLOAD_SYSTEM = """You are a penetration tester generating specific attack payloads for a confirmed vulnerability.
Generate 5-10 targeted payloads based on the vulnerability type and context.
Respond ONLY with valid JSON: {"payloads": ["payload1", "payload2", ...], "technique": "brief explanation"}"""

NARRATOR_SYSTEM = """You are writing the executive summary section of a professional penetration test report.
Write in clear, business-appropriate language. Be specific about risks and impacts.
Do not use markdown. Use plain paragraphs. Be concise but thorough."""


class PayloadRequest(BaseModel):
    finding_title: str
    finding_description: str
    severity: str
    endpoint: Optional[str] = None
    method: Optional[str] = None
    module: str
    owasp_ref: Optional[str] = None
    cwe_id: Optional[str] = None
    existing_evidence: Optional[str] = None


class PayloadResponse(BaseModel):
    payloads: list[str]
    technique: str


async def generate_payloads(req: PayloadRequest) -> PayloadResponse:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not api_key:
        return PayloadResponse(
            payloads=["[AI unavailable] Configure ANTHROPIC_API_KEY"],
            technique="AI payload generation requires ANTHROPIC_API_KEY",
        )

    context = f"""Vulnerability: {req.finding_title}
Severity: {req.severity}
Module: {req.module}
Endpoint: {req.endpoint or 'N/A'}
Method: {req.method or 'N/A'}
Description: {req.finding_description}
OWASP: {req.owasp_ref or 'N/A'}
CWE: {req.cwe_id or 'N/A'}
Evidence: {req.existing_evidence or 'N/A'}

Generate specific attack payloads to confirm and exploit this vulnerability."""

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=PAYLOAD_SYSTEM,
        messages=[{"role": "user", "content": context}],
    )

    text = message.content[0].text.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:-1])

    data = json.loads(text)
    return PayloadResponse(
        payloads=data.get("payloads", []),
        technique=data.get("technique", ""),
    )


# ─── Report narrator ──────────────────────────────────────────────────────────

class TopFinding(BaseModel):
    title: str
    severity: str
    cvss_score: Optional[float] = None
    endpoint: Optional[str] = None
    description: str
    ai_remediation: Optional[str] = None


class ScanSummary(BaseModel):
    scan_name: str
    target_count: int
    modules_run: list[str]
    stats: dict[str, int]
    duration_mins: Optional[float] = None
    pci_findings_count: int = 0
    failure_count: int = 0


class NarrateRequest(BaseModel):
    scan_id: str
    summary: ScanSummary
    top_findings: list[TopFinding]


class NarrateResponse(BaseModel):
    scan_id: str
    executive_summary: str
    critical_section: str
    remediation_priorities: str
    pci_narrative: Optional[str] = None


async def narrate_findings(req: NarrateRequest) -> NarrateResponse:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    fallback = (
        f"Security assessment of {req.summary.target_count} API targets completed. "
        f"Findings: {req.summary.stats}. Configure ANTHROPIC_API_KEY for AI narrative generation."
    )

    if not api_key:
        return NarrateResponse(
            scan_id=req.scan_id,
            executive_summary=fallback,
            critical_section="AI narrative requires ANTHROPIC_API_KEY.",
            remediation_priorities="Configure ANTHROPIC_API_KEY to enable AI report narration.",
        )

    client = anthropic.Anthropic(api_key=api_key)

    stats_str = ", ".join(f"{k}: {v}" for k, v in req.summary.stats.items() if v > 0)
    findings_str = "\n".join(
        f"- [{f.severity.upper()}] {f.title} (CVSS: {f.cvss_score or 'N/A'}) — {f.description[:200]}"
        for f in req.top_findings[:15]
    )

    context = f"""Scan name: {req.summary.scan_name}
Target APIs assessed: {req.summary.target_count}
Modules run: {', '.join(req.summary.modules_run)}
Duration: {req.summary.duration_mins or 'N/A'} minutes
Finding severity breakdown: {stats_str}
PCI DSS findings: {req.summary.pci_findings_count}
Failed scans: {req.summary.failure_count}

Top findings:
{findings_str}"""

    # Executive summary
    exec_msg = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=NARRATOR_SYSTEM + "\nWrite the executive summary (3-4 paragraphs) for this penetration test report.",
        messages=[{"role": "user", "content": context}],
    )
    executive_summary = exec_msg.content[0].text.strip()

    # Critical findings narrative
    crit_msg = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=NARRATOR_SYSTEM + "\nWrite a narrative describing the critical and high severity findings and their business impact.",
        messages=[{"role": "user", "content": context}],
    )
    critical_section = crit_msg.content[0].text.strip()

    # Remediation priorities
    rem_msg = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=NARRATOR_SYSTEM + "\nWrite a prioritized remediation roadmap with immediate actions (0-30 days), short-term (30-90 days), and long-term (90+ days).",
        messages=[{"role": "user", "content": context}],
    )
    remediation_priorities = rem_msg.content[0].text.strip()

    # PCI narrative if applicable
    pci_narrative = None
    if req.summary.pci_findings_count > 0:
        pci_msg = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=400,
            system=NARRATOR_SYSTEM + "\nWrite the PCI DSS compliance section summarizing gaps and remediation required before a QSA assessment.",
            messages=[{"role": "user", "content": context}],
        )
        pci_narrative = pci_msg.content[0].text.strip()

    return NarrateResponse(
        scan_id=req.scan_id,
        executive_summary=executive_summary,
        critical_section=critical_section,
        remediation_priorities=remediation_priorities,
        pci_narrative=pci_narrative,
    )
