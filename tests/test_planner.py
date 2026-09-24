import pytest
from app.models.finding import VulnerabilityFinding
from app.planner.optimizer import RemediationOptimizer

@pytest.fixture
def user_dataset():
    return [
        VulnerabilityFinding(
            finding_id="VULN-722BEF", target="127.0.0.1", port=80, service="http",
            vulnerability="Vuln 1", cvss=9.5, exploitability=9.5, asset_criticality=10.0,
            exposure=1.0, business_risk=95.0, severity="CRITICAL", evidence="Header",
            remediation_effort=3.0
        ),
        VulnerabilityFinding(
            finding_id="VULN-D8AA6F", target="127.0.0.1", port=22, service="ssh",
            vulnerability="Vuln 2", cvss=4.0, exploitability=4.0, asset_criticality=10.0,
            exposure=1.0, business_risk=40.0, severity="HIGH", evidence="Header",
            remediation_effort=2.0
        ),
        VulnerabilityFinding(
            finding_id="VULN-246DB4", target="127.0.0.1", port=3306, service="mysql",
            vulnerability="Vuln 3", cvss=9.0, exploitability=9.0, asset_criticality=10.0,
            exposure=1.0, business_risk=90.0, severity="CRITICAL", evidence="Header",
            remediation_effort=4.0
        ),
        VulnerabilityFinding(
            finding_id="VULN-BC4456", target="127.0.0.1", port=5432, service="postgresql",
            vulnerability="Vuln 4", cvss=8.0, exploitability=8.0, asset_criticality=10.0,
            exposure=1.0, business_risk=80.0, severity="CRITICAL", evidence="Header",
            remediation_effort=6.0
        ),
        VulnerabilityFinding(
            finding_id="VULN-0CBF86", target="127.0.0.1", port=445, service="smb",
            vulnerability="Vuln 5", cvss=7.5, exploitability=7.5, asset_criticality=10.0,
            exposure=1.0, business_risk=75.0, severity="CRITICAL", evidence="Header",
            remediation_effort=5.0
        )
    ]

def test_user_dataset_capacity_5h(user_dataset):
    """
    Capacity = 5h.
    Expected: VULN-722BEF (3h, 95) + VULN-D8AA6F (2h, 40)
    Total Effort = 5h, Total BRS = 135
    """
    plan = RemediationOptimizer.optimize_plan(user_dataset, available_capacity=5.0)
    selected_ids = set([f.finding_id for f in plan.selected_vulnerabilities])
    
    assert selected_ids == {"VULN-722BEF", "VULN-D8AA6F"}
    assert plan.total_effort_used == 5.0
    assert plan.remaining_capacity == 0.0
    assert plan.total_risk_reduced == 135.0
    assert "VULN-246DB4" not in selected_ids
    assert plan.optimization_rationale is not None

def test_user_dataset_capacity_4h(user_dataset):
    """
    Capacity = 4h.
    Expected: VULN-722BEF (3h, 95)
    Total Effort = 3h, Total BRS = 95
    """
    plan = RemediationOptimizer.optimize_plan(user_dataset, available_capacity=4.0)
    selected_ids = set([f.finding_id for f in plan.selected_vulnerabilities])
    
    assert selected_ids == {"VULN-722BEF"}
    assert plan.total_effort_used == 3.0
    assert plan.remaining_capacity == 1.0
    assert plan.total_risk_reduced == 95.0

def test_user_dataset_capacity_6h(user_dataset):
    """
    Capacity = 6h.
    Expected: VULN-722BEF (3h, 95) + VULN-D8AA6F (2h, 40)
    Total Effort = 5h, Total BRS = 135
    """
    plan = RemediationOptimizer.optimize_plan(user_dataset, available_capacity=6.0)
    selected_ids = set([f.finding_id for f in plan.selected_vulnerabilities])
    
    assert selected_ids == {"VULN-722BEF", "VULN-D8AA6F"}
    assert plan.total_effort_used == 5.0
    assert plan.remaining_capacity == 1.0
    assert plan.total_risk_reduced == 135.0

def test_user_dataset_capacity_7h(user_dataset):
    """
    Capacity = 7h.
    Expected: VULN-722BEF (3h, 95) + VULN-246DB4 (4h, 90)
    Total Effort = 7h, Total BRS = 185
    """
    plan = RemediationOptimizer.optimize_plan(user_dataset, available_capacity=7.0)
    selected_ids = set([f.finding_id for f in plan.selected_vulnerabilities])
    
    assert selected_ids == {"VULN-722BEF", "VULN-246DB4"}
    assert plan.total_effort_used == 7.0
    assert plan.remaining_capacity == 0.0
    assert plan.total_risk_reduced == 185.0

def test_user_dataset_capacity_9h(user_dataset):
    """
    Capacity = 9h.
    Expected: VULN-722BEF (3h, 95) + VULN-246DB4 (4h, 90) + VULN-D8AA6F (2h, 40)
    Total Effort = 9h, Total BRS = 225
    """
    plan = RemediationOptimizer.optimize_plan(user_dataset, available_capacity=9.0)
    selected_ids = set([f.finding_id for f in plan.selected_vulnerabilities])
    
    assert selected_ids == {"VULN-722BEF", "VULN-246DB4", "VULN-D8AA6F"}
    assert plan.total_effort_used == 9.0
    assert plan.remaining_capacity == 0.0
    assert plan.total_risk_reduced == 225.0

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
