from typing import List
from app.models.finding import VulnerabilityFinding

class BusinessRiskEngine:
    """
    Transparent Business-Risk Scoring Engine for HTH-CS-03.
    Calculates Business Risk Score = Exploitability * Asset Criticality * Exposure.
    Ranks findings by business impact instead of raw CVSS alone.
    """

    @staticmethod
    def calculate_risk(finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """
        Calculates BRS and updates severity tier for a single finding.
        """
        # Ensure values are within expected ranges
        e = max(1.0, min(10.0, finding.exploitability))
        c = max(1.0, min(10.0, finding.asset_criticality))
        x = max(0.1, min(1.0, finding.exposure))

        brs = round(e * c * x, 2)
        finding.business_risk = brs

        # Severity categorization based on Business Risk Score
        if brs >= 70.0:
            finding.severity = "CRITICAL"
        elif brs >= 40.0:
            finding.severity = "HIGH"
        elif brs >= 15.0:
            finding.severity = "MEDIUM"
        else:
            finding.severity = "LOW"

        return finding

    @classmethod
    def rank_findings(cls, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """
        Calculates business risk for all findings and sorts them descending by Business Risk Score.
        """
        scored_findings = [cls.calculate_risk(f) for f in findings]
        # Sort primarily by Business Risk Score descending, secondary by CVSS descending
        return sorted(scored_findings, key=lambda f: (f.business_risk or 0.0, f.cvss or 0.0), reverse=True)
