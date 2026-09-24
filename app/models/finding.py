from pydantic import BaseModel, Field
from typing import Optional, List

class VulnerabilityFinding(BaseModel):
    finding_id: str = Field(..., description="Unique identifier for the finding")
    cve_id: Optional[str] = Field(default=None, description="CVE ID if applicable (e.g. CVE-2011-2523)")
    target: str = Field(..., description="IP address or hostname of the lab target")
    port: int = Field(..., description="Port number")
    service: str = Field(..., description="Service name e.g., http, ssh, ftp")
    version: Optional[str] = Field(default="Unknown", description="Service version")
    vulnerability: str = Field(..., description="Short title/description of vulnerability")
    cvss: Optional[float] = Field(default=0.0, description="Raw CVSS v3 score (0.0 - 10.0)")
    exploitability: float = Field(..., description="Exploitability factor (1.0 - 10.0)")
    asset_criticality: float = Field(..., description="Asset criticality weight (1.0 - 10.0)")
    exposure: float = Field(..., description="Exposure factor (0.1 - 1.0)")
    business_risk: Optional[float] = Field(default=0.0, description="Calculated Business Risk Score")
    severity: Optional[str] = Field(default="INFO", description="Calculated Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    evidence: str = Field(..., description="Evidence/banner output captured during scan")
    
    # Sprint 2 & 3 Remediation Attributes
    remediation_effort: float = Field(default=4.0, description="Estimated remediation effort in hours")
    remediation_action: Optional[str] = Field(default="Apply security patch and update service version", description="Recommended remediation action")
    remediation_status: Optional[str] = Field(default="PENDING", description="Remediation status: SELECTED, DEFERRED, PENDING")

    # Sprint 4 Threat Intelligence Attributes
    kev_known_exploited: bool = Field(default=False, description="True if CVE exists in CISA KEV catalog")
    kev_date_added: Optional[str] = Field(default=None, description="CISA KEV date added")
    kev_due_date: Optional[str] = Field(default=None, description="CISA KEV remediation due date")
    kev_required_action: Optional[str] = Field(default=None, description="CISA KEV required action")
    epss_score: Optional[float] = Field(default=None, description="FIRST EPSS exploit probability (0.0 - 1.0)")
    epss_percentile: Optional[float] = Field(default=None, description="FIRST EPSS percentile (0.0 - 1.0)")
    threat_intel_multiplier: float = Field(default=1.0, description="Threat intelligence adjustment multiplier")
    threat_intel_last_updated: Optional[str] = Field(default=None, description="Timestamp of threat intel lookup")

class ScanRequest(BaseModel):
    target: str = Field(..., description="IP or hostname of lab target")
    asset_criticality: float = Field(default=5.0, description="Asset Criticality (1.0 - 10.0)")
    exposure: float = Field(default=0.5, description="Exposure Factor (0.1 - 1.0)")
    enrich_threat_intel: bool = Field(default=True, description="Whether to enrich findings with CISA KEV & FIRST EPSS threat intelligence")

class PlanRequest(BaseModel):
    scan_id: Optional[str] = Field(default=None, description="Optional scan_id to generate plan from")
    target: Optional[str] = Field(default="192.168.1.10", description="Target IP or hostname")
    asset_criticality: float = Field(default=5.0, description="Asset Criticality (1.0 - 10.0)")
    exposure: float = Field(default=0.5, description="Exposure Factor (0.1 - 1.0)")
    available_capacity: float = Field(default=15.0, description="Available remediation capacity in hours")
    findings: Optional[List[VulnerabilityFinding]] = Field(default=None, description="Optional custom findings list")

class RemediationPlan(BaseModel):
    plan_id: Optional[str] = Field(default=None, description="Persisted plan UUID")
    scan_id: Optional[str] = Field(default=None, description="Persisted scan UUID")
    available_capacity: float = Field(..., description="Total available capacity in hours")
    total_effort_used: float = Field(..., description="Total hours used by selected remediations")
    remaining_capacity: float = Field(..., description="Remaining unused capacity in hours")
    total_risk_reduced: float = Field(..., description="Sum of Business Risk Scores of selected remediations")
    total_initial_risk: float = Field(..., description="Sum of Business Risk Scores across all findings")
    risk_reduction_percentage: float = Field(..., description="Percentage of total risk eliminated")
    selected_count: int = Field(..., description="Number of vulnerabilities selected for sprint")
    deferred_count: int = Field(..., description="Number of vulnerabilities deferred")
    selected_vulnerabilities: List[VulnerabilityFinding] = Field(..., description="Vulnerabilities selected for current sprint")
    deferred_vulnerabilities: List[VulnerabilityFinding] = Field(..., description="Vulnerabilities deferred to future sprint")
    optimization_rationale: Optional[str] = Field(default=None, description="Detailed optimization rationale explaining trade-offs")
