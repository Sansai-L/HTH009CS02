import pytest
from app.models.finding import VulnerabilityFinding
from app.threat_intel.kev import CisaKevClient
from app.threat_intel.epss import FirstEpssClient
from app.threat_intel.service import ThreatIntelligenceService
from app.risk_engine.scorer import BusinessRiskEngine
from app.planner.optimizer import RemediationOptimizer

def test_kev_lookup_known_and_unknown_cves():
    # Known KEV CVE
    known = CisaKevClient.lookup_cve("CVE-2021-41773")
    assert known is not None
    assert known["cve_id"] == "CVE-2021-41773"

    # Unknown / Non-KEV CVE
    unknown = CisaKevClient.lookup_cve("CVE-1999-0000")
    assert unknown is None

def test_epss_lookup_known_and_unknown_cves():
    # EPSS batch lookup
    epss_results = FirstEpssClient.lookup_epss_batch(["CVE-2021-41773", "CVE-1999-0000"])
    assert "CVE-2021-41773" in epss_results
    assert epss_results["CVE-2021-41773"]["epss_score"] is not None
    assert epss_results["CVE-2021-41773"]["epss_score"] > 0.0

def test_threat_intel_service_enrichment():
    finding = VulnerabilityFinding(
        finding_id="TEST-001",
        cve_id="CVE-2021-41773",
        target="127.0.0.1",
        port=80,
        service="http",
        version="Apache 2.4.49",
        vulnerability="Apache RCE",
        cvss=7.5,
        exploitability=8.0,
        asset_criticality=10.0,
        exposure=1.0,
        evidence="HTTP Header"
    )

    enriched = ThreatIntelligenceService.enrich_findings([finding])[0]
    assert enriched.kev_known_exploited is True
    assert enriched.epss_score is not None
    assert enriched.epss_score > 0.5
    assert enriched.threat_intel_last_updated is not None

def test_brs_threat_multiplier_calculation():
    finding_no_threat = VulnerabilityFinding(
        finding_id="TEST-BASE",
        target="127.0.0.1", port=80, service="http", vulnerability="Base Test",
        cvss=7.0, exploitability=7.0, asset_criticality=10.0, exposure=1.0, evidence="Banner",
        kev_known_exploited=False, epss_score=None
    )
    scored_base = BusinessRiskEngine.calculate_risk(finding_no_threat)
    # Base BRS = 7.0 * 10.0 * 1.0 = 70.0, Multiplier = 1.0
    assert scored_base.threat_intel_multiplier == 1.0
    assert scored_base.business_risk == 70.0

    finding_with_threat = VulnerabilityFinding(
        finding_id="TEST-THREAT",
        target="127.0.0.1", port=80, service="http", vulnerability="Threat Test",
        cvss=7.0, exploitability=7.0, asset_criticality=10.0, exposure=1.0, evidence="Banner",
        kev_known_exploited=True,  # +0.5 boost
        epss_score=0.96            # +0.48 boost -> Multiplier = 1.0 + 0.48 + 0.5 = 1.98
    )
    scored_threat = BusinessRiskEngine.calculate_risk(finding_with_threat)
    assert scored_threat.threat_intel_multiplier == 1.98
    assert scored_threat.business_risk == round(70.0 * 1.98, 2)  # 138.6

def test_ranking_case_a_vs_case_b():
    """
    Case A: High CVSS (9.8), Low EPSS (0.12), Not KEV -> Base BRS = 4.0 * 10.0 * 0.5 = 20.0, Multiplier = 1.06 -> Final = 21.2
    Case B: Lower CVSS (7.5), High EPSS (0.96), KEV = True -> Base BRS = 8.0 * 10.0 * 0.5 = 40.0, Multiplier = 1.98 -> Final = 79.2
    Case B MUST rank higher than Case A despite lower CVSS.
    """
    case_a = VulnerabilityFinding(
        finding_id="CASE-A",
        cve_id="CVE-2008-0166",
        target="127.0.0.1", port=22, service="ssh", vulnerability="High CVSS Low Threat",
        cvss=9.8, exploitability=4.0, asset_criticality=10.0, exposure=0.5, evidence="Banner",
        kev_known_exploited=False, epss_score=0.12
    )

    case_b = VulnerabilityFinding(
        finding_id="CASE-B",
        cve_id="CVE-2021-41773",
        target="127.0.0.1", port=80, service="http", vulnerability="Lower CVSS Active KEV",
        cvss=7.5, exploitability=8.0, asset_criticality=10.0, exposure=0.5, evidence="Banner",
        kev_known_exploited=True, epss_score=0.96
    )

    ranked = BusinessRiskEngine.rank_findings([case_a, case_b])
    
    assert ranked[0].finding_id == "CASE-B"
    assert ranked[0].business_risk > ranked[1].business_risk

def test_optimizer_uses_threat_intel_priorities():
    """
    Verifies that the 0/1 Knapsack optimizer consumes threat-intelligence-enriched BRS values.
    """
    case_a = VulnerabilityFinding(
        finding_id="LOW-THREAT-ITEM",
        cve_id="CVE-2008-0166",
        target="127.0.0.1", port=22, service="ssh", vulnerability="Low Threat",
        cvss=9.8, exploitability=4.0, asset_criticality=10.0, exposure=0.5, evidence="Banner",
        remediation_effort=5.0, kev_known_exploited=False, epss_score=0.10
    )

    case_b = VulnerabilityFinding(
        finding_id="HIGH-THREAT-ITEM",
        cve_id="CVE-2021-41773",
        target="127.0.0.1", port=80, service="http", vulnerability="High Threat KEV",
        cvss=7.5, exploitability=8.0, asset_criticality=10.0, exposure=0.5, evidence="Banner",
        remediation_effort=5.0, kev_known_exploited=True, epss_score=0.95
    )

    findings = [case_a, case_b]
    enriched = ThreatIntelligenceService.enrich_findings(findings)
    scored = [BusinessRiskEngine.calculate_risk(f) for f in enriched]
    ranked = BusinessRiskEngine.rank_findings(scored)

    # With 5h capacity, optimizer should select HIGH-THREAT-ITEM because its threat-boosted BRS is higher
    plan = RemediationOptimizer.optimize_plan(ranked, available_capacity=5.0)
    assert plan.selected_count == 1
    assert plan.selected_vulnerabilities[0].finding_id == "HIGH-THREAT-ITEM"
