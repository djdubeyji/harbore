"""
Harbore AI Module — FastAPI server
Provides: finding enrichment, RAG Q&A, payload generation, report narration
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

from modules.enrichment import enrich_findings, EnrichRequest, EnrichResponse
from modules.rag        import answer_question, RAGRequest, RAGResponse
from modules.payload    import generate_payloads, PayloadRequest, PayloadResponse
from modules.narrator   import narrate_findings, NarrateRequest, NarrateResponse

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def verify_internal_token(request):
    """Verify the internal WORKER_TOKEN header for service-to-service calls."""
    token = request.headers.get("X-Internal-Token", "")
    expected = os.getenv("WORKER_TOKEN", "")
    if expected and token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


@asynccontextmanager
async def lifespan(app: FastAPI):
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        log.warning("ANTHROPIC_API_KEY not set — AI features will be unavailable")
    else:
        log.info("AI module ready with Anthropic API")
    yield


app = FastAPI(
    title="Harbore AI",
    version="1.0.0",
    description="AI enrichment and analysis for Harbore security scans",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "harbore-ai"}


@app.post("/ai/enrich", response_model=EnrichResponse)
async def enrich(req: EnrichRequest):
    """
    Enrich findings with AI-generated summaries, remediation, and priority scores.
    Input: list of raw findings from scanner
    Output: same findings with ai_summary, ai_remediation, ai_priority fields populated
    """
    return await enrich_findings(req)


@app.post("/ai/ask", response_model=RAGResponse)
async def ask(req: RAGRequest):
    """
    Answer a natural language question about the current scan using RAG.
    Input: question + full findings context
    Output: AI answer with source citations
    """
    return await answer_question(req)


@app.post("/ai/payloads", response_model=PayloadResponse)
async def payloads(req: PayloadRequest):
    """
    Generate context-aware attack payloads for a specific finding.
    Input: finding details + target context
    Output: list of suggested payloads to try
    """
    return await generate_payloads(req)


@app.post("/ai/narrate", response_model=NarrateResponse)
async def narrate(req: NarrateRequest):
    """
    Generate executive narrative and remediation text for the report.
    Input: scan summary + top findings
    Output: executive summary text + section narratives per severity
    """
    return await narrate_findings(req)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8090"))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
