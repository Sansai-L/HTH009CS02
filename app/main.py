from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from typing import List, Dict, Any
import os

from app.models.finding import ScanRequest, VulnerabilityFinding
from app.guardrail.validator import is_authorized_lab_target
from app.scanner.lab_scanner import LabScanner
from app.risk_engine.scorer import BusinessRiskEngine

app = FastAPI(
    title="HTH-CS-03: Business-Risk-Ranked Vulnerability Scanner",
    description="Phase 1 Vertical Slice — Business-Context Risk Engine & Lab Scanner Pipeline",
    version="1.0.0"
)

# Template configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "ui", "templates"))

@app.get("/", response_class=HTMLResponse)
def render_dashboard(request: Request):
    """
    Renders the basic functional interface for Phase 1.
    """
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/health")
def health_check():
    return {"status": "ok", "phase": "1 - Architecture & Prototyping Vertical Slice"}

@app.post("/api/scan")
def run_scan(request: ScanRequest) -> Dict[str, Any]:
    """
    Scans an authorized lab target, normalizes findings, computes Business Risk Scores,
    and returns findings sorted descending by business risk.
    """
    # 1. Target Authorization Guardrail Check
    is_auth, message = is_authorized_lab_target(request.target)
    if not is_auth:
        raise HTTPException(status_code=403, detail=message)

    try:
        # 2. Execute Scanner & Schema Normalizer
        raw_findings = LabScanner.scan_target(
            target=request.target,
            asset_criticality=request.asset_criticality,
            exposure=request.exposure,
            use_mock=True
        )

        # 3. Calculate Business Risk Scores & Rank Findings
        ranked_findings = BusinessRiskEngine.rank_findings(raw_findings)

        return {
            "status": "success",
            "target": request.target,
            "guardrail_verification": message,
            "total_findings": len(ranked_findings),
            "findings": [f.model_dump() for f in ranked_findings]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
