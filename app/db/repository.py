import json
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import uuid

from app.db.models import AssetDB, ScanJobDB, VulnerabilityFindingDB, RemediationPlanDB
from app.models.finding import VulnerabilityFinding, RemediationPlan

class DatabaseRepository:

    @staticmethod
    def get_or_create_asset(db: Session, target: str, criticality: float, exposure: float) -> AssetDB:
        asset = db.query(AssetDB).filter(AssetDB.ip_address == target).first()
        if not asset:
            asset = AssetDB(
                asset_id=str(uuid.uuid4()),
                ip_address=target,
                hostname=target,
                criticality_score=criticality,
                exposure_level=exposure,
                authorization_status="AUTHORIZED_LAB"
            )
            db.add(asset)
        else:
            asset.criticality_score = criticality
            asset.exposure_level = exposure
        db.commit()
        db.refresh(asset)
        return asset

    @classmethod
    def save_scan(cls, db: Session, target: str, criticality: float, exposure: float, findings: list[VulnerabilityFinding]) -> ScanJobDB:
        asset = cls.get_or_create_asset(db, target, criticality, exposure)

        scan_job = ScanJobDB(
            scan_id=str(uuid.uuid4()),
            asset_id=asset.asset_id,
            target=target,
            status="COMPLETED",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc)
        )
        db.add(scan_job)
        db.flush()

        for f in findings:
            v_db = VulnerabilityFindingDB(
                finding_id=f.finding_id,
                scan_id=scan_job.scan_id,
                cve_id=getattr(f, "cve_id", f.finding_id),
                target=f.target,
                port=f.port,
                service=f.service,
                version=f.version,
                vulnerability=f.vulnerability,
                cvss=f.cvss or 0.0,
                exploitability=f.exploitability,
                asset_criticality=f.asset_criticality,
                exposure=f.exposure,
                business_risk=f.business_risk or 0.0,
                severity=f.severity or "INFO",
                evidence=f.evidence,
                remediation_effort=f.remediation_effort,
                remediation_action=f.remediation_action
            )
            db.add(v_db)

        db.commit()
        db.refresh(scan_job)
        return scan_job

    @staticmethod
    def save_plan(db: Session, scan_id: str, plan: RemediationPlan) -> RemediationPlanDB:
        selected_json = json.dumps([f.model_dump() for f in plan.selected_vulnerabilities])
        deferred_json = json.dumps([f.model_dump() for f in plan.deferred_vulnerabilities])

        plan_db = RemediationPlanDB(
            plan_id=str(uuid.uuid4()),
            scan_id=scan_id,
            available_capacity=plan.available_capacity,
            total_effort_used=plan.total_effort_used,
            remaining_capacity=plan.remaining_capacity,
            total_risk_reduced=plan.total_risk_reduced,
            total_initial_risk=plan.total_initial_risk,
            risk_reduction_percentage=plan.risk_reduction_percentage,
            selected_count=plan.selected_count,
            deferred_count=plan.deferred_count,
            selected_vulnerabilities_json=selected_json,
            deferred_vulnerabilities_json=deferred_json,
            optimization_rationale=plan.optimization_rationale,
            created_at=datetime.now(timezone.utc)
        )
        db.add(plan_db)
        db.commit()
        db.refresh(plan_db)
        return plan_db

    @staticmethod
    def get_latest_plan(db: Session) -> RemediationPlanDB | None:
        return db.query(RemediationPlanDB).order_by(RemediationPlanDB.created_at.desc()).first()

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: str) -> ScanJobDB | None:
        return db.query(ScanJobDB).filter(ScanJobDB.scan_id == scan_id).first()

    @staticmethod
    def get_all_assets(db: Session) -> list[AssetDB]:
        return db.query(AssetDB).all()
