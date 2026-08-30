"""
Finding enrichment — AI-generated summaries, remediation, and CVSS re-scoring.
"""
import os
import json
import logging
from typing import Optional
from pydantic import BaseModel
import anthropic

log = logging.getLogger(__name__)

SEV_PRIORITY = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}

SYSTEM_PROMPT = """You are a senior penetration tester and security engineer reviewing API vulnerability findings.
Your job is to:
1. Write a concise technical summary (2-3 sentences) of the finding
2. Write actionable remediation steps specific to the vulnerability
3. Assign a priority score (1-10) based on exploitability, impact, and context

Respond ONLY with valid JSON, no markdown, no preamble:
{
  "summary": "...",
  "remediation": "...",
  "priority": 7
}"""


class FindingInput(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float] = None
    endpoint: Optional[str] = None
    module: Optional[str] = None
    owasp_ref: Optional[str] = None
    pci_requirement: Optional[str] = None
    cwe_id: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None


class FindingEnriched(FindingInput):
    ai_summary: Optional[str] = None
    ai_remediation: Optional[str] = None
    ai_priority: Optional[int] = None


class EnrichRequest(BaseModel):
    scan_id: str
    findings: list[FindingInput]
    # Limit enrichment to top N findings to control cost
    max_findings: int = 50


class EnrichResponse(BaseModel):
    scan_id: str
    enriched: list[FindingEnriched]
    enriched_count: int
    skipped_count: int


async def enrich_findings(req: EnrichRequest) -> EnrichResponse:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    enriched = []
    skipped = 0

    # Sort by severity, take top N
    sorted_findings = sorted(
        req.findings,
        key=lambda f: SEV_PRIORITY.get(f.severity, 0),
        reverse=True
    )[:req.max_findings]

    skipped = len(req.findings) - len(sorted_findings)

    if not api_key:
        # No API key — return findings with placeholder enrichment
        for f in sorted_findings:
            ef = FindingEnriched(**f.model_dump())
            ef.ai_summary = f"[AI unavailable] {f.title} — {f.description[:200]}"
            ef.ai_remediation = "Configure ANTHROPIC_API_KEY to enable AI remediation."
            ef.ai_priority = SEV_PRIORITY.get(f.severity, 1)
            enriched.append(ef)
        return EnrichResponse(
            scan_id=req.scan_id,
            enriched=enriched,
            enriched_count=len(enriched),
            skipped_count=skipped,
        )

    client = anthropic.Anthropic(api_key=api_key)

    for finding in sorted_findings:
        try:
            ef = await _enrich_one(client, finding)
            enriched.append(ef)
        except Exception as e:
            log.warning(f"Enrichment failed for finding {finding.id}: {e}")
            ef = FindingEnriched(**finding.model_dump())
            ef.ai_priority = SEV_PRIORITY.get(finding.severity, 1)
            enriched.append(ef)

    return EnrichResponse(
        scan_id=req.scan_id,
        enriched=enriched,
        enriched_count=len(enriched),
        skipped_count=skipped,
    )


async def _enrich_one(client: anthropic.Anthropic, f: FindingInput) -> FindingEnriched:
    context_parts = [
        f"Title: {f.title}",
        f"Severity: {f.severity}",
        f"Module: {f.module or 'unknown'}",
        f"Description: {f.description}",
        f"Endpoint: {f.endpoint or 'N/A'}",
    ]
    if f.cvss_score:
        context_parts.append(f"CVSS Score: {f.cvss_score}")
    if f.owasp_ref:
        context_parts.append(f"OWASP Reference: {f.owasp_ref}")
    if f.pci_requirement:
        context_parts.append(f"PCI DSS: {f.pci_requirement}")
    if f.cwe_id:
        context_parts.append(f"CWE: {f.cwe_id}")
    if f.request:
        context_parts.append(f"Request evidence: {f.request[:500]}")
    if f.response:
        context_parts.append(f"Response evidence: {f.response[:500]}")

    user_message = "Enrich this security finding:\n\n" + "\n".join(context_parts)

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    text = message.content[0].text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()

    data = json.loads(text)
    ef = FindingEnriched(**f.model_dump())
    ef.ai_summary     = data.get("summary", "")
    ef.ai_remediation = data.get("remediation", "")
    ef.ai_priority    = int(data.get("priority", SEV_PRIORITY.get(f.severity, 1)))
    return ef
