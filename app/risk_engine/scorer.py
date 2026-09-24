from typing import List
from app.models.finding import VulnerabilityFinding

class BusinessRiskEngine:
    """
    Transparent Business-Risk Scoring Engine for HTH-CS-03 (Sprint 4 Threat Intelligence Integration).
    
    Formula:
      Base BRS = Exploitability * Asset Criticality * Exposure
      Threat Multiplier = 1.0 + (EPSS Score * 0.5) + (0.5 if KEV Known Exploited else 0.0)
      Final Business Risk Score (BRS) = Base BRS * Threat Multiplier
    
    This preserves exact backward compatibility (Threat Multiplier = 1.0 when threat intel is absent),
    while transparently boosting priority for vulnerabilities with active in-the-wild exploitation (KEV)
    or high exploitation probability (EPSS).
    """

    @staticmethod
    def calculate_risk(finding: VulnerabilityFinding) -> VulnerabilityFinding:
        """
        Calculates Base BRS, Threat Intelligence Multiplier, Final BRS, and updates Severity tier.
        """
        # 1. Base Business Risk Score Calculation
        e = max(1.0, min(10.0, finding.exploitability))
        c = max(1.0, min(10.0, finding.asset_criticality))
        x = max(0.1, min(1.0, finding.exposure))

        base_brs = e * c * x

        # 2. Threat Intelligence Multiplier
        epss_contribution = (finding.epss_score * 0.5) if (finding.epss_score is not None) else 0.0
        kev_boost = 0.5 if finding.kev_known_exploited else 0.0

        multiplier = round(1.0 + epss_contribution + kev_boost, 2)
        finding.threat_intel_multiplier = multiplier

        # 3. Final Business Risk Score
        final_brs = round(base_brs * multiplier, 2)
        finding.business_risk = final_brs

        # 4. Severity categorization based on Final Business Risk Score
        if final_brs >= 70.0:
            finding.severity = "CRITICAL"
        elif final_brs >= 40.0:
            finding.severity = "HIGH"
        elif final_brs >= 15.0:
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
        return sorted(scored_findings, key=lambda f: (f.business_risk or 0.0, f.cvss or 0.0), reverse=True)
