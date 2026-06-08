import logging
from typing import Dict, Any

import config

logger = logging.getLogger(__name__)


class ThreatIntelEnricher:
    def __init__(self):
        # Load local threat feed database from config
        self.threat_db = config.LOCAL_THREAT_FEEDS

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
        Checks a domain and its resolved IP addresses against threat feeds.
        Returns an aggregated threat intelligence dictionary.
        """

        # Default benign telemetry structure
        threat_telemetry = {
            "is_in_threat_feed": False,
            "threat_category": "none",
            "feed_source": "none",
            "reputation_score": 0,
            "reputation_level": "BENIGN",
            "malicious_votes": 0,
            "suspicious_votes": 0
        }

        # -------------------------
        # Domain Match
        # -------------------------
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

                    return threat_telemetry

        # -------------------------
        # IP Match
        # -------------------------
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

        return threat_telemetry