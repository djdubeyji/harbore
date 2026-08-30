"""
RAG (Retrieval-Augmented Generation) — answer questions about the current scan.
The full findings are passed as context (no vector DB needed for typical scan sizes).
"""
import os
import json
import logging
from typing import Optional
from pydantic import BaseModel
import anthropic

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a security analyst assistant with access to the full findings of a security scan.
Answer questions about the scan concisely and accurately. Reference specific findings where relevant.
If asked about remediation, provide concrete, actionable advice.
Format your response in plain text, not markdown."""


class FindingSummary(BaseModel):
    title: str
    severity: str
    module: str
    endpoint: Optional[str] = None
    cvss_score: Optional[float] = None
    owasp_ref: Optional[str] = None
    pci_requirement: Optional[str] = None
    description: str


class RAGRequest(BaseModel):
    scan_id: str
    scan_name: str
    question: str
    findings: list[FindingSummary]
    stats: dict[str, int] = {}


class RAGResponse(BaseModel):
    scan_id: str
    question: str
    answer: str
    model: str = "claude-sonnet-4-20250514"


async def answer_question(req: RAGRequest) -> RAGResponse:
    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if not api_key:
        return RAGResponse(
            scan_id=req.scan_id,
            question=req.question,
            answer="AI Q&A is unavailable — configure ANTHROPIC_API_KEY to enable this feature.",
        )

    # Build findings context
    stats_text = ", ".join(f"{k}: {v}" for k, v in req.stats.items() if v > 0)
    context_lines = [
        f"Scan: {req.scan_name}",
        f"Finding counts by severity: {stats_text or 'none'}",
        f"Total findings: {len(req.findings)}",
        "",
        "FINDINGS:",
    ]

    for i, f in enumerate(req.findings[:100], 1):  # limit to 100 findings in context
        parts = [f"{i}. [{f.severity.upper()}] {f.title}"]
        if f.endpoint:
            parts.append(f"   Endpoint: {f.endpoint}")
        if f.cvss_score:
            parts.append(f"   CVSS: {f.cvss_score}")
        if f.owasp_ref:
            parts.append(f"   OWASP: {f.owasp_ref}")
        if f.pci_requirement:
            parts.append(f"   PCI: {f.pci_requirement}")
        parts.append(f"   {f.description[:300]}")
        context_lines.extend(parts)

    context = "\n".join(context_lines)
    user_message = f"Scan context:\n{context}\n\nQuestion: {req.question}"

    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_message}],
    )

    answer = message.content[0].text.strip()
    return RAGResponse(scan_id=req.scan_id, question=req.question, answer=answer)
