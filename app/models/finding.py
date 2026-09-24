from pydantic import BaseModel, Field
from typing import Optional

class VulnerabilityFinding(BaseModel):
    finding_id: str = Field(..., description="Unique identifier for the finding")
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

class ScanRequest(BaseModel):
    target: str = Field(..., description="IP or hostname of lab target")
    asset_criticality: float = Field(default=5.0, description="Asset Criticality (1.0 - 10.0)")
    exposure: float = Field(default=0.5, description="Exposure Factor (0.1 - 1.0)")
