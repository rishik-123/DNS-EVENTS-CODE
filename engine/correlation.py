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
        self.historical_tracker = HistoricalTracker()

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

        # 5. Fetch WHOIS Enrichment
        whois_info = self.whois_enricher.enrich_domain(query)

        # 6. Fetch GeoIP Enrichment for response IPs
        response_ips = raw_event.get("response_ip", [])
        resolved_locations = []
        for ip in response_ips:
            loc = self.geoip_enricher.enrich_ip(ip)
            resolved_locations.append({
                "ip": ip,
                "country": loc.get("country", "unknown"),
                "city": loc.get("city", "unknown"),
                "asn": loc.get("asn", "unknown")
            })

        # 7. Fetch Threat Intelligence Matches
        threat_info = self.threat_enricher.enrich_entity(query, response_ips)

        # 8. Fetch Asset and User Context
        context_info = self.asset_enricher.enrich_context(username)

        # 9. Update and Fetch Historical Context
        history_info = self.historical_tracker.update_and_get_stats(query, timestamp_str)

        # 10. Run Tunneling Detector Heuristics
        is_tunneling, tunneling_score, payload_size = analyze_tunneling(
            query,
            query_type,
            history_info["query_rate_per_minute"],
            history_info["unique_subdomains_count"]
        )

        # 11. Core Security Alerts Triage
        alerts = []
        if is_tunneling:
            alerts.append("DNS_TUNNELING_SUSPECT")
        if is_dga:
            alerts.append("DGA_BEACONING_SUSPECT")
        if is_typosquat:
            alerts.append("TYPOSQUATTING_IMPERSONATION")
        if threat_info["is_in_threat_feed"]:
            alerts.append(f"THREAT_INTEL_MATCH_{threat_info['threat_category'].upper()}")
        if raw_event.get("response_code") == "NXDOMAIN" and history_info["query_rate_per_minute"] > 10.0:
            alerts.append("HIGH_NXDOMAIN_RATE_ANOMALY")
        if raw_event.get("ttl", 100) < 15 and raw_event.get("ttl", 100) > 0:
            alerts.append("SUSPICIOUS_LOW_TTL_FAST_FLUX")

        # Compile Consolidated SOC Event Schema
        soc_event = {
            # Meta Header
            "event_id": event_id,
            "timestamp": timestamp_str,
            "alerts": alerts,
            
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
                "typosquat_target": typosquat_target or "none"
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
                "business_unit": context_info["asset_context"]["business_unit"],
                "department": context_info["asset_context"]["department"]
            },
            
            # Threat Intelligence Layer
            "threat_intel": {
                "is_in_threat_feed": threat_info["is_in_threat_feed"],
                "threat_category": threat_info["threat_category"],
                "feed_source": threat_info["feed_source"],
                "reputation_score": threat_info["reputation_score"],
                "malicious_votes": threat_info["malicious_votes"],
                "suspicious_votes": threat_info["suspicious_votes"]
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
