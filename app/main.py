from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from typing import List, Dict, Any
import os

from app.models.finding import ScanRequest, PlanRequest, RemediationPlan, VulnerabilityFinding
from app.guardrail.validator import is_authorized_lab_target
from app.scanner.lab_scanner import LabScanner
from app.risk_engine.scorer import BusinessRiskEngine
from app.planner.optimizer import RemediationOptimizer

app = FastAPI(
    title="HTH-CS-03: Business-Risk-Ranked Vulnerability Scanner & Remediation Planner",
    description="Sprint 2 — Business-Context Risk Engine, Lab Scanner, and Capacity-Constrained Remediation Planner",
    version="2.0.0"
)

# Template configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "ui", "templates"))

@app.get("/", response_class=HTMLResponse)
def render_dashboard(request: Request):
    """
    Renders the interactive web dashboard.
    """
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "sprint": "2 - Core Development (Remediation Planner Active)",
        "version": "2.0.0"
    }

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

@app.post("/api/plan")
def generate_remediation_plan(request: PlanRequest) -> RemediationPlan:
    """
    Generates an optimized capacity-constrained remediation plan using 0/1 Knapsack optimization.
    Inputs: target, asset_criticality, exposure, available_capacity (hours), optional findings.
    Outputs: selected remediations, deferred remediations, effort used, remaining capacity, risk reduced %.
    """
    is_auth, message = is_authorized_lab_target(request.target or "192.168.1.10")
    if not is_auth:
        raise HTTPException(status_code=403, detail=message)

    try:
        if request.findings:
            findings = [BusinessRiskEngine.calculate_risk(f) for f in request.findings]
            ranked_findings = BusinessRiskEngine.rank_findings(findings)
        else:
            raw_findings = LabScanner.scan_target(
                target=request.target or "192.168.1.10",
                asset_criticality=request.asset_criticality,
                exposure=request.exposure,
                use_mock=True
            )
            ranked_findings = BusinessRiskEngine.rank_findings(raw_findings)

        plan = RemediationOptimizer.optimize_plan(
            findings=ranked_findings,
            available_capacity=request.available_capacity
        )
        return plan

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
