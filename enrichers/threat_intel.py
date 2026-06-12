import os
import json
import logging
import requests
from datetime import datetime
from typing import Dict, Any

import config

logger = logging.getLogger(__name__)


class ThreatIntelEnricher:
    def __init__(self):
        # Load local threat feed database from config
        self.threat_db = config.LOCAL_THREAT_FEEDS
        self.vt_cache_path = config.VT_CACHE_FILE
        self.vt_api_key = config.VT_API_KEY
        self.vt_cache = self._load_vt_cache()

    def _load_vt_cache(self) -> Dict[str, Any]:
        """Loads VirusTotal cache from disk."""
        if os.path.exists(self.vt_cache_path):
            try:
                with open(self.vt_cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading VT cache: {e}")
        return {}

    def _save_vt_cache(self):
        """Saves VirusTotal cache to disk."""
        try:
            with open(self.vt_cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.vt_cache, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving VT cache: {e}")

    def query_virustotal(self, domain: str) -> Dict[str, Any]:
        """
        Queries VirusTotal API v3 for domain reputation.
        Caches results locally to avoid redundant API queries.
        """
        empty_vt = {
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "reputation": 0,
            "is_malicious": False,
            "harmless_votes": 0,
            "undetected_votes": 0
        }
        
        if not domain or domain.lower() in ["localhost", "127.0.0.1"] or domain.lower().endswith(".local") or "." not in domain:
            return empty_vt

        domain_lower = domain.lower().strip()

        # Check if it is a known popular brand to avoid VT query latency
        is_popular = any(domain_lower == brand or domain_lower.endswith("." + brand) for brand in config.POPULAR_BRANDS)
        if is_popular:
            return empty_vt

        # Check Cache first
        if domain_lower in self.vt_cache:
            cache_entry = self.vt_cache[domain_lower]
            cached_time = datetime.fromisoformat(cache_entry.get("cached_at", datetime.utcnow().isoformat()))
            # If cache is less than 3 days old, reuse it
            if (datetime.utcnow() - cached_time).days < 3:
                return cache_entry["vt_data"]

        # Call VirusTotal v3 API
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain_lower}"
            headers = {
                "x-apikey": self.vt_api_key,
                "accept": "application/json"
            }
            logger.debug(f"Querying VirusTotal for {domain_lower}...")
            # Use a strict 3.0 second timeout
            response = requests.get(url, headers=headers, timeout=3.0)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                # Flag as malicious if at least 1 engine detects it
                is_malicious = malicious >= 1
                
                vt_data = {
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "reputation": reputation,
                    "is_malicious": is_malicious,
                    "harmless_votes": harmless,
                    "undetected_votes": undetected
                }
                
                # Save to cache
                self.vt_cache[domain_lower] = {
                    "vt_data": vt_data,
                    "cached_at": datetime.utcnow().isoformat()
                }
                self._save_vt_cache()
                return vt_data
            elif response.status_code == 404:
                # Domain not found on VT, cache as benign
                self.vt_cache[domain_lower] = {
                    "vt_data": empty_vt,
                    "cached_at": datetime.utcnow().isoformat()
                }
                self._save_vt_cache()
                return empty_vt
            else:
                logger.warning(f"VirusTotal query failed with status code {response.status_code}: {response.text}")
                return empty_vt
        except Exception as e:
            logger.error(f"Error querying VirusTotal for {domain_lower}: {e}")
            return empty_vt

    def _calculate_reputation_level(self, score: int) -> str:
        """
        Converts numeric reputation score into analyst-friendly severity.
        """
        if score >= 40:
            return "CRITICAL"
        elif score >= 25:
            return "HIGH"
        elif score >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    def enrich_entity(self, domain: str, ips: list) -> Dict[str, Any]:
        """
        Checks a domain and its resolved IP addresses against local threat feeds and VirusTotal.
        Returns an aggregated threat intelligence dictionary.
        """

        # Default benign telemetry structure
        threat_telemetry = {
            "is_in_threat_feed": False,
            "threat_category": "none",
            "feed_source": "none",
            "reputation_level": "BENIGN",
            "reputation_score": 0,  # 0 (good) to 100 (critical threat)
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "vt_checked": False,
            "vt_malicious": False
        }

        # 1. Check local threat feeds first (extremely fast)
        if domain:
            domain_lower = domain.lower()

            if domain_lower in self.threat_db:
                feed_match = self.threat_db[domain_lower]

                threat_telemetry.update({
                    "is_in_threat_feed": True,
                    "threat_category": feed_match.get(
                        "category",
                        "malicious"
                    ),
                    "feed_source": feed_match.get(
                        "source",
                        "Local Threat Intel"
                    ),
                    "reputation_score": feed_match.get(
                        "reputation_score",
                        10
                    ),
                    "malicious_votes": feed_match.get(
                        "malicious_votes",
                        1
                    ),
                    "suspicious_votes": feed_match.get(
                        "suspicious_votes",
                        0
                    )
                })

                threat_telemetry["reputation_level"] = (
                    self._calculate_reputation_level(
                        threat_telemetry["reputation_score"]
                    )
                )

                # Still check VT if domain is matched, to get full telemetry
                vt_res = self.query_virustotal(domain)
                threat_telemetry.update({
                    "vt_checked": True,
                    "vt_malicious": vt_res["is_malicious"],
                    "malicious_votes": max(threat_telemetry["malicious_votes"], vt_res["malicious_votes"]),
                    "suspicious_votes": max(threat_telemetry["suspicious_votes"], vt_res["suspicious_votes"])
                })
                return threat_telemetry

            # -------------------------
            # Wildcard Match
            # -------------------------
            for feed_domain, feed_match in self.threat_db.items():

                if domain_lower.endswith("." + feed_domain):

                    threat_telemetry.update({
                        "is_in_threat_feed": True,
                        "threat_category": feed_match.get(
                            "category",
                            "malicious"
                        ),
                        "feed_source": feed_match.get(
                            "source",
                            "Local Threat Intel"
                        ),
                        "reputation_score": feed_match.get(
                            "reputation_score",
                            10
                        ),
                        "malicious_votes": feed_match.get(
                            "malicious_votes",
                            1
                        ),
                        "suspicious_votes": feed_match.get(
                            "suspicious_votes",
                            0
                        )
                    })

                    threat_telemetry["reputation_level"] = (
                        self._calculate_reputation_level(
                            threat_telemetry["reputation_score"]
                        )
                    )

        # -------------------------
        # IP Match
        # -------------------------
                    vt_res = self.query_virustotal(domain)
                    threat_telemetry.update({
                        "vt_checked": True,
                        "vt_malicious": vt_res["is_malicious"],
                        "malicious_votes": max(threat_telemetry["malicious_votes"], vt_res["malicious_votes"]),
                        "suspicious_votes": max(threat_telemetry["suspicious_votes"], vt_res["suspicious_votes"])
                    })
                    return threat_telemetry
        # 2. Check resolved IPs in local threat feeds
        if ips:

            for ip in ips:

                if ip in self.threat_db:

                    feed_match = self.threat_db[ip]

                    threat_telemetry.update({
                        "is_in_threat_feed": True,
                        "threat_category": feed_match.get(
                            "category",
                            "malicious_infrastructure"
                        ),
                        "feed_source": feed_match.get(
                            "source",
                            "Local GeoIP Feed"
                        ),
                        "reputation_score": feed_match.get(
                            "reputation_score",
                            15
                        ),
                        "malicious_votes": feed_match.get(
                            "malicious_votes",
                            5
                        ),
                        "suspicious_votes": feed_match.get(
                            "suspicious_votes",
                            1
                        )
                    })

                    threat_telemetry["reputation_level"] = (
                        self._calculate_reputation_level(
                            threat_telemetry["reputation_score"]
                        )
                    )

                    return threat_telemetry

        # 3. Check VirusTotal if local feeds didn't match
        if domain:
            vt_res = self.query_virustotal(domain)
            if vt_res["is_malicious"]:
                threat_telemetry.update({
                    "is_in_threat_feed": True,
                    "threat_category": "malicious_website",
                    "feed_source": "VirusTotal API",
                    "reputation_score": min(100, vt_res["malicious_votes"] * 10),
                    "malicious_votes": vt_res["malicious_votes"],
                    "suspicious_votes": vt_res["suspicious_votes"],
                    "vt_checked": True,
                    "vt_malicious": True
                })

                threat_telemetry["reputation_level"] = (
                    self._calculate_reputation_level(
                        threat_telemetry["reputation_score"]
                    )
                )

            else:
                threat_telemetry.update({
                    "vt_checked": True,
                    "vt_malicious": False,
                    "malicious_votes": vt_res["malicious_votes"],
                    "suspicious_votes": vt_res["suspicious_votes"]
                })

        return threat_telemetry
