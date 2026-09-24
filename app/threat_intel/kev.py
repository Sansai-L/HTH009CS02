import requests
import json
import os
import time
from typing import Dict, Any, Optional

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE = os.path.join(os.path.dirname(__file__), "cisa_kev_cache.json")
CACHE_TTL = 86400  # 24 hours

class CisaKevClient:
    """
    Client for CISA Known Exploited Vulnerabilities (KEV) Catalog.
    Downloads and caches the official CISA KEV JSON dataset locally to prevent repeated network calls.
    Gracefully handles offline/network errors by utilizing local cache or fallback signatures.
    """
    _cache: Dict[str, Dict[str, Any]] = {}
    _last_fetched: float = 0.0

    @classmethod
    def load_cache_from_disk(cls) -> bool:
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    cls._cache = data.get("vulnerabilities", {})
                    cls._last_fetched = data.get("last_fetched", 0.0)
                    return True
            except Exception:
                pass
        return False

    @classmethod
    def save_cache_to_disk(cls):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "last_fetched": cls._last_fetched,
                    "vulnerabilities": cls._cache
                }, f, indent=2)
        except Exception:
            pass

    @classmethod
    def fetch_catalog(cls, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        now = time.time()
        
        # Load from disk if memory cache is empty
        if not cls._cache:
            cls.load_cache_from_disk()

        # Check if cache is fresh and force refresh is False
        if cls._cache and not force_refresh and (now - cls._last_fetched < CACHE_TTL):
            return cls._cache

        try:
            response = requests.get(CISA_KEV_URL, timeout=5.0)
            if response.status_code == 200:
                json_data = response.json()
                vulns = json_data.get("vulnerabilities", [])
                
                new_cache = {}
                for item in vulns:
                    cve = item.get("cveID", "").upper()
                    if cve:
                        new_cache[cve] = {
                            "cve_id": cve,
                            "date_added": item.get("dateAdded"),
                            "due_date": item.get("dueDate"),
                            "vendor_project": item.get("vendorProject"),
                            "product": item.get("product"),
                            "vulnerability_name": item.get("vulnerabilityName"),
                            "short_description": item.get("shortDescription"),
                            "required_action": item.get("requiredAction")
                        }
                cls._cache = new_cache
                cls._last_fetched = now
                cls.save_cache_to_disk()
                return cls._cache
        except Exception:
            # Fall back to disk cache if network fails
            if cls._cache:
                return cls._cache

        # Fallback dataset for standard lab CVEs if network is completely offline and no disk cache exists
        if not cls._cache:
            cls._cache = {
                "CVE-2011-2523": {"cve_id": "CVE-2011-2523", "date_added": "2021-11-03", "due_date": "2022-05-03", "required_action": "Apply update per vendor instructions."},
                "CVE-2007-2447": {"cve_id": "CVE-2007-2447", "date_added": "2021-11-03", "due_date": "2022-05-03", "required_action": "Apply update per vendor instructions."},
                "CVE-2021-41773": {"cve_id": "CVE-2021-41773", "date_added": "2021-10-05", "due_date": "2021-10-20", "required_action": "Upgrade Apache httpd to 2.4.50 or later."},
                "CVE-2012-2122": {"cve_id": "CVE-2012-2122", "date_added": "2022-01-18", "due_date": "2022-07-18", "required_action": "Apply security patch."},
                "CVE-2022-0543": {"cve_id": "CVE-2022-0543", "date_added": "2022-04-18", "due_date": "2022-05-02", "required_action": "Apply security patch."},
                "CVE-2017-5638": {"cve_id": "CVE-2017-5638", "date_added": "2021-11-03", "due_date": "2022-05-03", "required_action": "Apply security patch."}
            }
        return cls._cache

    @classmethod
    def lookup_cve(cls, cve_id: str) -> Optional[Dict[str, Any]]:
        if not cve_id:
            return None
        catalog = cls.fetch_catalog()
        return catalog.get(cve_id.upper().strip())
