import pytest
from app.models.finding import VulnerabilityFinding
from app.planner.optimizer import RemediationOptimizer

def test_zero_capacity_defers_all():
    findings = [
        VulnerabilityFinding(
            finding_id="V1", target="127.0.0.1", port=80, service="http",
            vulnerability="Vuln 1", cvss=7.5, exploitability=8.0, asset_criticality=10.0,
            exposure=1.0, business_risk=80.0, severity="CRITICAL", evidence="Header",
            remediation_effort=4.0
        )
    ]
    plan = RemediationOptimizer.optimize_plan(findings, available_capacity=0.0)
    assert plan.available_capacity == 0.0
    assert plan.total_effort_used == 0.0
    assert plan.selected_count == 0
    assert plan.deferred_count == 1
    assert plan.risk_reduction_percentage == 0.0
    assert plan.deferred_vulnerabilities[0].remediation_status == "DEFERRED"

def test_single_vulnerability_within_capacity():
    finding = VulnerabilityFinding(
        finding_id="V1", target="127.0.0.1", port=80, service="http",
        vulnerability="Vuln 1", cvss=7.5, exploitability=8.0, asset_criticality=10.0,
        exposure=1.0, business_risk=80.0, severity="CRITICAL", evidence="Header",
        remediation_effort=4.0
    )
    plan = RemediationOptimizer.optimize_plan([finding], available_capacity=5.0)
    assert plan.selected_count == 1
    assert plan.deferred_count == 0
    assert plan.total_effort_used == 4.0
    assert plan.remaining_capacity == 1.0
    assert plan.total_risk_reduced == 80.0
    assert plan.risk_reduction_percentage == 100.0

def test_single_vulnerability_exceeds_capacity():
    finding = VulnerabilityFinding(
        finding_id="V1", target="127.0.0.1", port=80, service="http",
        vulnerability="Vuln 1", cvss=7.5, exploitability=8.0, asset_criticality=10.0,
        exposure=1.0, business_risk=80.0, severity="CRITICAL", evidence="Header",
        remediation_effort=10.0
    )
    plan = RemediationOptimizer.optimize_plan([finding], available_capacity=5.0)
    assert plan.selected_count == 0
    assert plan.deferred_count == 1
    assert plan.total_effort_used == 0.0
    assert plan.remaining_capacity == 5.0

def test_knapsack_superiority_over_highest_brs():
    """
    Test case where highest BRS is NOT chosen because its effort is too large,
    but two smaller effort vulnerabilities yield a higher combined risk reduction.
    """
    finding_high_brs = VulnerabilityFinding(
        finding_id="HIGH-BRS-HEAVY", target="127.0.0.1", port=80, service="http",
        vulnerability="Heavy Vuln", cvss=9.0, exploitability=9.0, asset_criticality=10.0,
        exposure=1.0, business_risk=90.0, severity="CRITICAL", evidence="Header",
        remediation_effort=20.0  # Requires 20 hours
    )

    finding_b = VulnerabilityFinding(
        finding_id="MEDIUM-1", target="127.0.0.1", port=3306, service="mysql",
        vulnerability="Medium Vuln B", cvss=7.0, exploitability=7.0, asset_criticality=7.0,
        exposure=1.0, business_risk=50.0, severity="HIGH", evidence="Header",
        remediation_effort=5.0   # Requires 5 hours
    )

    finding_c = VulnerabilityFinding(
        finding_id="MEDIUM-2", target="127.0.0.1", port=21, service="ftp",
        vulnerability="Medium Vuln C", cvss=6.5, exploitability=6.5, asset_criticality=7.0,
        exposure=1.0, business_risk=45.0, severity="HIGH", evidence="Header",
        remediation_effort=5.0   # Requires 5 hours
    )

    findings = [finding_high_brs, finding_b, finding_c]
    # Available Capacity: 10.0 Hours
    plan = RemediationOptimizer.optimize_plan(findings, available_capacity=10.0)

    # 0/1 Knapsack MUST pick B (50.0) + C (45.0) = 95.0 total risk reduced within 10 hours!
    selected_ids = [f.finding_id for f in plan.selected_vulnerabilities]
    assert "MEDIUM-1" in selected_ids
    assert "MEDIUM-2" in selected_ids
    assert "HIGH-BRS-HEAVY" not in selected_ids
    assert plan.total_effort_used == 10.0
    assert plan.total_risk_reduced == 95.0  # 95.0 > 90.0
