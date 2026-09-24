from sqlalchemy import Column, String, Float, Integer, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import uuid
from app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class AssetDB(Base):
    __tablename__ = "assets"

    asset_id = Column(String, primary_key=True, default=generate_uuid)
    ip_address = Column(String, nullable=False, index=True)
    hostname = Column(String, nullable=True)
    criticality_score = Column(Float, nullable=False, default=5.0)
    exposure_level = Column(Float, nullable=False, default=0.5)
    authorization_status = Column(String, nullable=False, default="AUTHORIZED_LAB")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scans = relationship("ScanJobDB", back_populates="asset", cascade="all, delete-orphan")

class ScanJobDB(Base):
    __tablename__ = "scan_jobs"

    scan_id = Column(String, primary_key=True, default=generate_uuid)
    asset_id = Column(String, ForeignKey("assets.asset_id"), nullable=False)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False, default="COMPLETED")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    asset = relationship("AssetDB", back_populates="scans")
    findings = relationship("VulnerabilityFindingDB", back_populates="scan", cascade="all, delete-orphan")
    plans = relationship("RemediationPlanDB", back_populates="scan", cascade="all, delete-orphan")

class VulnerabilityFindingDB(Base):
    __tablename__ = "vulnerabilities"

    finding_id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scan_jobs.scan_id"), nullable=False)
    cve_id = Column(String, nullable=True)
    target = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    service = Column(String, nullable=False)
    version = Column(String, nullable=True)
    vulnerability = Column(String, nullable=False)
    cvss = Column(Float, nullable=False, default=0.0)
    exploitability = Column(Float, nullable=False, default=1.0)
    asset_criticality = Column(Float, nullable=False, default=5.0)
    exposure = Column(Float, nullable=False, default=0.5)
    business_risk = Column(Float, nullable=False, default=0.0)
    severity = Column(String, nullable=False, default="INFO")
    evidence = Column(Text, nullable=False)
    remediation_effort = Column(Float, nullable=False, default=4.0)
    remediation_action = Column(Text, nullable=True)

    # Sprint 4 Threat Intelligence Columns
    kev_known_exploited = Column(Boolean, nullable=False, default=False)
    kev_date_added = Column(String, nullable=True)
    kev_due_date = Column(String, nullable=True)
    kev_required_action = Column(Text, nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    threat_intel_multiplier = Column(Float, nullable=False, default=1.0)
    threat_intel_last_updated = Column(String, nullable=True)

    scan = relationship("ScanJobDB", back_populates="findings")

class RemediationPlanDB(Base):
    __tablename__ = "remediation_plans"

    plan_id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scan_jobs.scan_id"), nullable=False)
    available_capacity = Column(Float, nullable=False)
    total_effort_used = Column(Float, nullable=False)
    remaining_capacity = Column(Float, nullable=False)
    total_risk_reduced = Column(Float, nullable=False)
    total_initial_risk = Column(Float, nullable=False)
    risk_reduction_percentage = Column(Float, nullable=False)
    selected_count = Column(Integer, nullable=False)
    deferred_count = Column(Integer, nullable=False)
    selected_vulnerabilities_json = Column(Text, nullable=False)
    deferred_vulnerabilities_json = Column(Text, nullable=False)
    optimization_rationale = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    scan = relationship("ScanJobDB", back_populates="plans")
