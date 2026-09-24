from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import os
import json

from app.models.finding import ScanRequest, PlanRequest, RemediationPlan, VulnerabilityFinding
from app.guardrail.validator import is_authorized_lab_target
from app.scanner.lab_scanner import LabScanner
from app.risk_engine.scorer import BusinessRiskEngine
from app.planner.optimizer import RemediationOptimizer
from app.db.database import get_db, init_db
from app.db.repository import DatabaseRepository
from app.db.models import VulnerabilityFindingDB

app = FastAPI(
    title="HTH-CS-03: Business-Risk-Ranked Vulnerability Scanner & Remediation Planner",
    description="Sprint 3 — Integrated Database Persistence & Capacity Remediation Platform",
    version="3.0.0"
)

# Initialize SQLite Database Tables on Module Load
init_db()

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
        "sprint": "3 - Full Integration & Persistence Active",
        "version": "3.0.0"
    }

@app.post("/api/scan")
def run_scan(request: ScanRequest, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Scans an authorized lab target, normalizes findings, computes Business Risk Scores,
    persists Asset, ScanJob, and Findings into SQLite database, and returns scan_id with findings.
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

        # 4. Persist Asset, ScanJob & Findings to SQLite
        scan_job = DatabaseRepository.save_scan(
            db=db,
            target=request.target,
            criticality=request.asset_criticality,
            exposure=request.exposure,
            findings=ranked_findings
        )

        return {
            "status": "success",
            "scan_id": scan_job.scan_id,
            "target": request.target,
            "guardrail_verification": message,
            "total_findings": len(ranked_findings),
            "findings": [f.model_dump() for f in ranked_findings]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/plan")
def generate_remediation_plan(request: PlanRequest, db: Session = Depends(get_db)) -> RemediationPlan:
    """
    Generates an optimized capacity-constrained remediation plan using 0/1 Knapsack optimization,
    persists the resulting plan in SQLite, and returns the plan.
    """
    is_auth, message = is_authorized_lab_target(request.target or "192.168.1.10")
    if not is_auth:
        raise HTTPException(status_code=403, detail=message)

    try:
        scan_id = request.scan_id

        if request.findings:
            findings = [BusinessRiskEngine.calculate_risk(f) for f in request.findings]
            ranked_findings = BusinessRiskEngine.rank_findings(findings)
        elif scan_id:
            scan_job = DatabaseRepository.get_scan_by_id(db, scan_id)
            if scan_job and scan_job.findings:
                ranked_findings = [
                    VulnerabilityFinding(
                        finding_id=f.finding_id,
                        target=f.target,
                        port=f.port,
                        service=f.service,
                        version=f.version,
                        vulnerability=f.vulnerability,
                        cvss=f.cvss,
                        exploitability=f.exploitability,
                        asset_criticality=f.asset_criticality,
                        exposure=f.exposure,
                        business_risk=f.business_risk,
                        severity=f.severity,
                        evidence=f.evidence,
                        remediation_effort=f.remediation_effort,
                        remediation_action=f.remediation_action
                    ) for f in scan_job.findings
                ]
                ranked_findings = BusinessRiskEngine.rank_findings(ranked_findings)
            else:
                raw_findings = LabScanner.scan_target(
                    target=request.target or "192.168.1.10",
                    asset_criticality=request.asset_criticality,
                    exposure=request.exposure,
                    use_mock=True
                )
                ranked_findings = BusinessRiskEngine.rank_findings(raw_findings)
        else:
            raw_findings = LabScanner.scan_target(
                target=request.target or "192.168.1.10",
                asset_criticality=request.asset_criticality,
                exposure=request.exposure,
                use_mock=True
            )
            ranked_findings = BusinessRiskEngine.rank_findings(raw_findings)

        # Optimize plan via 0/1 Knapsack
        plan = RemediationOptimizer.optimize_plan(
            findings=ranked_findings,
            available_capacity=request.available_capacity
        )

        # Create scan record if scan_id not present
        if not scan_id:
            scan_job = DatabaseRepository.save_scan(
                db=db,
                target=request.target or "192.168.1.10",
                criticality=request.asset_criticality,
                exposure=request.exposure,
                findings=ranked_findings
            )
            scan_id = scan_job.scan_id

        # Persist Plan to SQLite
        plan_db = DatabaseRepository.save_plan(db, scan_id, plan)
        plan.plan_id = plan_db.plan_id
        plan.scan_id = scan_id

        return plan

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/plan/latest")
def get_latest_remediation_plan(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """
    Retrieves the latest persisted remediation plan from SQLite database.
    Survives browser refresh and application restart.
    """
    plan_db = DatabaseRepository.get_latest_plan(db)
    if not plan_db:
        return {"status": "none", "message": "No persisted remediation plans found in database."}

    selected_raw = json.loads(plan_db.selected_vulnerabilities_json)
    deferred_raw = json.loads(plan_db.deferred_vulnerabilities_json)

    selected = [VulnerabilityFinding(**item) for item in selected_raw]
    deferred = [VulnerabilityFinding(**item) for item in deferred_raw]

    scan_job = plan_db.scan

    return {
        "status": "success",
        "plan_id": plan_db.plan_id,
        "scan_id": plan_db.scan_id,
        "target": scan_job.target if scan_job else "192.168.1.10",
        "available_capacity": plan_db.available_capacity,
        "total_effort_used": plan_db.total_effort_used,
        "remaining_capacity": plan_db.remaining_capacity,
        "total_risk_reduced": plan_db.total_risk_reduced,
        "total_initial_risk": plan_db.total_initial_risk,
        "risk_reduction_percentage": plan_db.risk_reduction_percentage,
        "selected_count": plan_db.selected_count,
        "deferred_count": plan_db.deferred_count,
        "selected_vulnerabilities": [f.model_dump() for f in selected],
        "deferred_vulnerabilities": [f.model_dump() for f in deferred],
        "optimization_rationale": plan_db.optimization_rationale
    }

@app.get("/api/assets")
def get_all_assets(db: Session = Depends(get_db)):
    """
    Retrieves all tracked assets from SQLite.
    """
    assets = DatabaseRepository.get_all_assets(db)
    return [
        {
            "asset_id": a.asset_id,
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "criticality_score": a.criticality_score,
            "exposure_level": a.exposure_level,
            "authorization_status": a.authorization_status,
            "scans_count": len(a.scans)
        } for a in assets
    ]
