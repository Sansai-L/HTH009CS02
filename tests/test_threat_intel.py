import pytest
from app.models.finding import VulnerabilityFinding
from app.threat_intel.kev import CisaKevClient
from app.threat_intel.epss import FirstEpssClient
from app.threat_intel.service import ThreatIntelligenceService
from app.risk_engine.scorer import BusinessRiskEngine
from app.planner.optimizer import RemediationOptimizer

def test_kev_lookup_known_and_unknown_cves():
    # Known KEV CVE (Log4Shell)
    kev_known = CisaKevClient.lookup_cve("CVE-2021-44228")
    assert kev_known is not None
    assert "date_added" in kev_known or "dateAdded" in kev_known or "required_action" in kev_known
    
    # Unknown CVE
    kev_unknown = CisaKevClient.lookup_cve("CVE-1999-0000-NONEXISTENT")
    assert kev_unknown is None

def test_epss_lookup_known_and_unknown_cves():
    # Known EPSS CVE
    epss_known = FirstEpssClient.lookup_epss("CVE-2021-44228")
    assert epss_known is not None
    assert epss_known["epss_score"] is not None
    assert epss_known["epss_score"] > 0.0

    # Unknown CVE
    epss_unknown = FirstEpssClient.lookup_epss("CVE-1999-0000-NONEXISTENT")
    assert epss_unknown is not None
    assert epss_unknown["epss_score"] is None

def test_threat_intel_service_enrichment():
    finding = VulnerabilityFinding(
        finding_id="TEST-KEV-EPSS",
        cve_id="CVE-2021-44228",
        target="192.168.1.10",
        port=8080,
        service="http-alt",
        version="Log4j 2.14.1",
        vulnerability="Log4Shell Remote Code Execution",
        cvss=10.0,
        exploitability=10.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="HTTP Header"
    )

    enriched = ThreatIntelligenceService.enrich_findings([finding])
    assert len(enriched) == 1
    e = enriched[0]
    assert e.kev_known_exploited is True
    assert e.epss_score is not None
    assert e.epss_score > 0.5
    assert e.threat_intel_last_updated is not None

def test_brs_threat_multiplier_calculation():
    # Finding with Base BRS = 10 * 10 * 1.0 = 100.0
    # KEV = True (+0.5), EPSS = 0.90 (+0.45) -> Multiplier = 1.0 + 0.5 + 0.45 = 1.95
    finding = VulnerabilityFinding(
        finding_id="TEST-MULT",
        cve_id="CVE-2021-44228",
        target="192.168.1.10",
        port=8080,
        service="http",
        vulnerability="Test Vuln",
        cvss=9.0,
        exploitability=10.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="Header",
        kev_known_exploited=True,
        epss_score=0.90
    )

    scored = BusinessRiskEngine.calculate_risk(finding)
    assert scored.threat_intel_multiplier == 1.95
    assert scored.business_risk == 195.0
    assert scored.severity == "CRITICAL"

def test_ranking_case_a_vs_case_b():
    # Case A: Base BRS = 80, but NO KEV & Low EPSS (0.1) -> Multiplier = 1.05 -> Final BRS = 84.0
    finding_a = VulnerabilityFinding(
        finding_id="CASE-A",
        cve_id="CVE-2008-0166",
        target="192.168.1.10",
        port=22,
        service="ssh",
        vulnerability="SSH Vuln",
        cvss=8.0,
        exploitability=8.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="Header",
        kev_known_exploited=False,
        epss_score=0.10
    )

    # Case B: Base BRS = 60, but Active KEV (+0.5) & High EPSS (0.95, +0.475) -> Multiplier = 1.98 -> Final BRS = 118.8
    finding_b = VulnerabilityFinding(
        finding_id="CASE-B",
        cve_id="CVE-2021-41773",
        target="192.168.1.10",
        port=80,
        service="http",
        vulnerability="Apache RCE",
        cvss=7.5,
        exploitability=6.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="Header",
        kev_known_exploited=True,
        epss_score=0.95
    )

    ranked = BusinessRiskEngine.rank_findings([finding_a, finding_b])
    # Case B must rank FIRST due to Threat Multiplier boosting Final BRS above Case A
    assert ranked[0].finding_id == "CASE-B"
    assert ranked[0].business_risk > ranked[1].business_risk

def test_optimizer_uses_threat_intel_priorities():
    finding_low_threat = VulnerabilityFinding(
        finding_id="LOW-THREAT",
        target="192.168.1.10",
        port=80,
        service="http",
        vulnerability="Vuln 1",
        cvss=8.0,
        exploitability=8.0,
        asset_criticality=10.0,
        exposure=1.0,
        business_risk=80.0, # Base BRS 80, no threat intel
        remediation_effort=4.0,
        evidence="Header"
    )

    finding_high_threat = VulnerabilityFinding(
        finding_id="HIGH-THREAT",
        target="192.168.1.10",
        port=443,
        service="https",
        vulnerability="Vuln 2",
        cvss=7.5,
        exploitability=7.0,
        asset_criticality=10.0,
        exposure=1.0,
        kev_known_exploited=True,
        epss_score=0.90, # Base BRS 70 * 1.95 = 136.5 Final BRS
        remediation_effort=4.0,
        evidence="Header"
    )

    scored = [BusinessRiskEngine.calculate_risk(f) for f in [finding_low_threat, finding_high_threat]]
    plan = RemediationOptimizer.optimize_plan(scored, available_capacity=4.0)

    selected_ids = [f.finding_id for f in plan.selected_vulnerabilities]
    assert selected_ids == ["HIGH-THREAT"]
    assert plan.total_risk_reduced == 136.5
