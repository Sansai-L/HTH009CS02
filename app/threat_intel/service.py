from typing import List
from datetime import datetime, timezone
from app.models.finding import VulnerabilityFinding
from app.threat_intel.kev import CisaKevClient
from app.threat_intel.epss import FirstEpssClient

class ThreatIntelligenceService:
    """
    Threat Intelligence Orchestrator Service.
    Enriches vulnerability findings with live/cached CISA KEV and FIRST EPSS metrics.
    """

    @classmethod
    def enrich_findings(cls, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        if not findings:
            return []

        # Gather all unique CVE IDs from findings
        cve_ids = [f.cve_id for f in findings if f.cve_id]
        
        # Batch EPSS lookup
        epss_map = FirstEpssClient.lookup_epss_batch(cve_ids) if cve_ids else {}
        now_str = datetime.now(timezone.utc).isoformat()

        for f in findings:
            if not f.cve_id:
                f.kev_known_exploited = False
                f.epss_score = None
                f.epss_percentile = None
                f.threat_intel_last_updated = now_str
                continue

            cve_clean = f.cve_id.upper().strip()

            # 1. KEV Catalog Lookup
            kev_data = CisaKevClient.lookup_cve(cve_clean)
            if kev_data:
                f.kev_known_exploited = True
                f.kev_date_added = kev_data.get("date_added")
                f.kev_due_date = kev_data.get("due_date")
                f.kev_required_action = kev_data.get("required_action")
            else:
                f.kev_known_exploited = False

            # 2. EPSS Lookup
            epss_data = epss_map.get(cve_clean)
            if epss_data and epss_data.get("epss_score") is not None:
                f.epss_score = epss_data.get("epss_score")
                f.epss_percentile = epss_data.get("epss_percentile")
            else:
                f.epss_score = None
                f.epss_percentile = None

            f.threat_intel_last_updated = now_str

        return findings
