import uuid
import logging
import tldextract
from datetime import datetime
from typing import Dict, Any

import config
from utils.entropy import calculate_entropy
from utils.typosquat import detect_typosquatting
from utils.dga import calculate_dga_score

from collectors.process_collector import get_process_metadata
from enrichers.whois_enricher import WHOISEnricher
from enrichers.geoip_enricher import GeoIPEnricher
from enrichers.threat_intel import ThreatIntelEnricher
from enrichers.asset_enricher import AssetEnricher
from enrichers.web_content_enricher import WebContentEnricher

from engine.tunneling_detector import analyze_tunneling
from engine.historical_tracker import HistoricalTracker

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self):
        logger.info("Initializing SOC Correlation Engine and Enrichers...")
        self.whois_enricher = WHOISEnricher()
        self.geoip_enricher = GeoIPEnricher()
        self.threat_enricher = ThreatIntelEnricher()
        self.asset_enricher = AssetEnricher()
        self.web_content_enricher = WebContentEnricher()
        self.historical_tracker = HistoricalTracker()
        
        import concurrent.futures
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=15, thread_name_prefix="enricher_worker")

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a raw DNS event, runs full enrichment pipeline, and outputs a normalized,
        structured SOC JSON security event.
        """
        # Generate Event ID and Timestamp
        event_id = str(uuid.uuid4())
        timestamp_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        query = raw_event.get("query", "")
        query_type = raw_event.get("query_type", "A")
        
        # 1. Parse Domain Layers
        domain_sld = "unknown"
        domain_tld = "unknown"
        subdomain = ""
        subdomain_length = 0
        query_length = len(query) if query else 0
        domain_entropy = 0.0
        
        if query:
            extracted = tldextract.extract(query.lower())
            domain_sld = extracted.domain or "unknown"
            domain_tld = f".{extracted.suffix}" if extracted.suffix else "unknown"
            subdomain = extracted.subdomain or ""
            subdomain_length = len(subdomain)
            domain_entropy = calculate_entropy(extracted.domain)

        # 2. Run DGA Analysis
        is_dga, dga_confidence = calculate_dga_score(query)

        # 3. Run Typosquatting Analysis
        is_typosquat, typosquat_target = detect_typosquatting(query, config.POPULAR_BRANDS)

        # 4. Fetch Process and Identity lineage
        pid = raw_event.get("pid", 0)
        process_info = get_process_metadata(pid)
        username = process_info.get("username", "unknown")

        # 5. Parallelize Slow network lookups (WHOIS, Threat Intel, Web Content, GeoIP)
        response_ips = raw_event.get("response_ip", [])
        
        # Helper to wrap GeoIP lookups
        def enrich_ip_wrapper(ip):
            loc = self.geoip_enricher.enrich_ip(ip)
            return {
                "ip": ip,
                "country": loc.get("country", "unknown"),
                "city": loc.get("city", "unknown"),
                "asn": loc.get("asn", "unknown")
            }

        # Submit enrichment tasks to thread pool
        future_whois = self.executor.submit(self.whois_enricher.enrich_domain, query)
        future_threat = self.executor.submit(self.threat_enricher.enrich_entity, query, response_ips)
        future_web_content = self.executor.submit(self.web_content_enricher.analyze_url_content, query)
        future_locations = [self.executor.submit(enrich_ip_wrapper, ip) for ip in response_ips]

        # 6. Fetch Asset and User Context (local, fast)
        context_info = self.asset_enricher.enrich_context(username)

        # 7. Update and Fetch Historical Context (local, fast)
        history_info = self.historical_tracker.update_and_get_stats(query, timestamp_str)

        # 8. Run Tunneling Detector Heuristics (local, fast)
        is_tunneling, tunneling_score, payload_size = analyze_tunneling(
            query,
            query_type,
            history_info["query_rate_per_minute"],
            history_info["unique_subdomains_count"]
        )
        risk_factors = []  

        # 9. Block and gather parallel lookup results (executing concurrently)
        whois_info = future_whois.result()
        threat_info = future_threat.result()
        web_content_info = future_web_content.result()
        resolved_locations = [f.result() for f in future_locations]

        # 12. Core Security Alerts Triage
        alerts = []
        correlation_rules = []
        if is_tunneling:
            alerts.append("DNS_TUNNELING_SUSPECT")
            risk_factors.append("DNS_TUNNELING")
        if is_dga:
            alerts.append("DGA_BEACONING_SUSPECT")
            risk_factors.append("DGA")
        if is_typosquat:
            alerts.append("TYPOSQUATTING_IMPERSONATION")
            risk_factors.append("TYPOSQUATTING")
        if threat_info["is_in_threat_feed"]:
            alerts.append(f"THREAT_INTEL_MATCH_{threat_info['threat_category'].upper()}")
            risk_factors.append("THREAT_INTEL_MATCH")
        if web_content_info["is_malicious"]:
            alerts.append("CORUNA_EXPLOIT_KIT_SUSPECT")
            risk_factors.append("CORUNA")
        if raw_event.get("response_code") == "NXDOMAIN" and history_info["query_rate_per_minute"] > 10.0:
            alerts.append("HIGH_NXDOMAIN_RATE_ANOMALY")
            risk_factors.append("HIGH_NXDOMAIN_RATE_ANOMALY")
        if raw_event.get("ttl", 100) < 15 and raw_event.get("ttl", 100) > 0:
            alerts.append("SUSPICIOUS_LOW_TTL_FAST_FLUX")
            risk_factors.append("SUSPICIOUS_LOW_TTL_FAST_FLUX")
        # Correlation Rules
        # Rule 1: Active DNS Exfiltration
        if (
            is_tunneling and
            history_info["query_rate_per_minute"] > 10
        ):
            correlation_rules.append({
                "rule_name": "ACTIVE_EXFILTRATION",
                "severity": "CRITICAL",
                "description": (
                    "Possible DNS data exfiltration detected "
                    "through sustained tunneling activity."
                )
            })


        # Rule 2: Fresh Typosquat Campaign
        if (
            is_typosquat and
            whois_info.get("is_newly_registered", False)
        ):
            correlation_rules.append({
                "rule_name": "FRESH_TYPOSQUAT_CAMPAIGN",
                "severity": "HIGH",
                "description": (
                    "Newly registered typosquatting domain "
                    "detected."
                )
            })


        # Rule 3: Fast Flux Infrastructure
        if (
            threat_info["is_in_threat_feed"] and
            raw_event.get("ttl", 100) < 15 and
            raw_event.get("ttl", 100) > 0
        ):
            correlation_rules.append({
                "rule_name": "FAST_FLUX_INFRASTRUCTURE",
                "severity": "HIGH",
                "description": (
                    "Threat intelligence match exhibiting "
                    "fast-flux behaviour."
                )
            })

        # 12. Risk Scoring
        risk_score = 0
        if is_tunneling:
            risk_score += 40

        if is_dga:
            risk_score += 25

        if is_typosquat:
            risk_score += 20

        if threat_info["is_in_threat_feed"]:
            risk_score += 35

        if whois_info.get("is_newly_registered", False):
            risk_score += 10
            risk_factors.append("NEWLY_REGISTERED_DOMAIN")
            
        if raw_event.get("ttl", 100) < 15:
            risk_score += 10

        risk_score = min(risk_score, 100)

        # 13. Severity Classification
        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Domain Risk Classification
        if risk_score >= 80:
            domain_risk_level = "CRITICAL"
        elif risk_score >= 60:
            domain_risk_level = "HIGH"
        elif risk_score >= 30:
            domain_risk_level = "MEDIUM"
        else:
            domain_risk_level = "LOW"

        # Compile Consolidated SOC Event Schema
        soc_event = {
            # Meta Header
            "event_id": event_id,
            "timestamp": timestamp_str,
            "alerts": alerts,

            "risk": {
                "score": risk_score,
                "severity": severity
            },
            "correlations": correlation_rules,

            # DNS Transaction Layer
            "dns": {
                "client_ip": raw_event.get("client_ip", "0.0.0.0"),
                "query": query,
                "query_type": query_type,
                "response_code": raw_event.get("response_code", "NOERROR"),
                "response_ip": response_ips,
                "response_cname": raw_event.get("response_cname", []),
                "ttl": raw_event.get("ttl", 0),
                "recursive": raw_event.get("recursive", True),
                "authoritative": raw_event.get("authoritative", False),
                "network_details": raw_event.get("network_details", {})
            },
            
            # Domain Characteristics Layer
            "domain_analysis": {
                "domain": domain_sld,
                "tld": domain_tld,
                "subdomain": subdomain,
                "subdomain_length": subdomain_length,
                "query_length": query_length,
                "domain_age_days": whois_info.get("domain_age_days", -1),
                "creation_date": whois_info.get("creation_date", "unknown"),
                "registrar": whois_info.get("registrar", "unknown"),
                "entropy": domain_entropy,
                "is_dga": is_dga,
                "dga_confidence": dga_confidence,
                "is_newly_registered": whois_info.get("is_newly_registered", False),
                "is_typosquat": is_typosquat,
                "typosquat_target": typosquat_target or "none",
                "domain_risk_level": domain_risk_level,
                "risk_factors": risk_factors
            },
            
            # Tunneling Detection Layer
            "tunneling_analysis": {
                "is_tunneling_suspect": is_tunneling,
                "tunneling_score": tunneling_score,
                "payload_size_bytes": payload_size,
                "unique_subdomains_count": history_info["unique_subdomains_count"],
                "query_rate_per_minute": history_info["query_rate_per_minute"]
            },
            
            # Process Lineage Layer
            "process": {
                "pid": process_info.get("pid", 0),
                "process_name": process_info.get("process_name", "unknown"),
                "parent_pid": process_info.get("parent_pid", 0),
                "parent_process": process_info.get("parent_process", "unknown"),
                "command_line": process_info.get("command_line", "unknown"),
                "exe_path": process_info.get("exe_path", "unknown"),
                "process_hash": process_info.get("process_hash", "unknown"),
                "process_sha256": process_info.get("process_sha256", "unknown"),
                "signer": process_info.get("signer", "unknown")
            },
            
            # Identity/User Context Layer
            "user": {
                "username": context_info["user_context"]["username"],
                "role": context_info["user_context"]["role"],
                "privilege": context_info["user_context"]["privilege"]
            },
            
            # Asset Context Layer
            "asset": {
                "hostname": context_info["asset_context"]["hostname"],
                "operating_system": context_info["asset_context"]["operating_system"],
                "os_version": context_info["asset_context"]["os_version"],
                "criticality": context_info["asset_context"]["criticality"],
                "criticality_score": context_info["asset_context"]["criticality_score"],
                "business_unit": context_info["asset_context"]["business_unit"],
                "department": context_info["asset_context"]["department"]
            },
            
            # Threat Intelligence Layer
            "threat_intel": {
                "is_in_threat_feed": threat_info["is_in_threat_feed"],
                "threat_category": threat_info["threat_category"],
                "feed_source": threat_info["feed_source"],
                "reputation_score": threat_info["reputation_score"],
                "reputation_level": threat_info["reputation_level"],
                "malicious_votes": threat_info["malicious_votes"],
                "suspicious_votes": threat_info["suspicious_votes"]
            },
            
            # Web Content Analysis Layer (Coruna indicators check)
            "web_content_analysis": {
                "checked": web_content_info["checked"],
                "is_malicious": web_content_info["is_malicious"],
                "matched_signatures": web_content_info["matched_signatures"],
                "status_code": web_content_info["status_code"],
                "error": web_content_info["error"]
            },
            
            # Geolocation Layer
            "geolocation": resolved_locations,
            
            # Historical Context Layer
            "history": {
                "first_seen": history_info["first_seen"],
                "last_seen": history_info["last_seen"],
                "frequency": history_info["frequency"]
            }
        }
        
        return soc_event
