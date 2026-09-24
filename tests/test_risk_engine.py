import pytest
from app.models.finding import VulnerabilityFinding
from app.risk_engine.scorer import BusinessRiskEngine

def test_business_risk_score_calculation():
    finding = VulnerabilityFinding(
        finding_id="TEST-001",
        target="192.168.1.10",
        port=80,
        service="http",
        version="Apache 2.4.18",
        vulnerability="Test HTTP Vuln",
        cvss=7.5,
        exploitability=8.0,
        asset_criticality=10.0, # High Criticality
        exposure=1.0,           # High Exposure
        evidence="HTTP Header Test"
    )

    scored = BusinessRiskEngine.calculate_risk(finding)
    # BRS = 8.0 * 10.0 * 1.0 = 80.0
    assert scored.business_risk == 80.0
    assert scored.severity == "CRITICAL"

def test_business_risk_reranking_over_cvss():
    # Finding A: High CVSS (9.8), but Low Criticality (2.0) and Low Exposure (0.1) -> BRS = 9.5 * 2.0 * 0.1 = 1.9
    finding_a = VulnerabilityFinding(
        finding_id="FINDING-A",
        target="192.168.1.50",
        port=21,
        service="ftp",
        version="vsftpd",
        vulnerability="Critical FTP Vuln on Dev Server",
        cvss=9.8,
        exploitability=9.5,
        asset_criticality=2.0,
        exposure=0.1,
        evidence="FTP Banner"
    )

    # Finding B: Medium CVSS (7.2), but High Criticality (10.0) and High Exposure (1.0) -> BRS = 7.0 * 10.0 * 1.0 = 70.0
    finding_b = VulnerabilityFinding(
        finding_id="FINDING-B",
        target="192.168.1.10",
        port=80,
        service="http",
        version="Apache",
        vulnerability="Medium Apache Vuln on Core Payment Gateway",
        cvss=7.2,
        exploitability=7.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="HTTP Banner"
    )

    ranked = BusinessRiskEngine.rank_findings([finding_a, finding_b])
    
    # Finding B must rank FIRST due to higher Business Risk Score (70.0 vs 1.9)
    assert ranked[0].finding_id == "FINDING-B"
    assert ranked[0].business_risk == 70.0
    assert ranked[1].finding_id == "FINDING-A"
    assert ranked[1].business_risk == 1.9
