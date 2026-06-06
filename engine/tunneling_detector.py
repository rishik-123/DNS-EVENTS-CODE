import re
import logging
from typing import Dict, Any, Tuple
import tldextract

import config
from utils.entropy import calculate_entropy

logger = logging.getLogger(__name__)

def estimate_payload_size(query: str, query_type: str) -> int:
    """
    Estimates the size in bytes of the hidden payload within a DNS query.
    For tunneling, data is encoded in the subdomain.
    """
    if not query:
        return 0
        
    extracted = tldextract.extract(query.lower())
    subdomain = extracted.subdomain
    
    if not subdomain:
        return 0
        
    # Standard DNS encoding uses base63 characters.
    # Base64 has a data density of ~0.75. Hex is 0.5.
    # Let's estimate based on character contents
    subdomain_clean = subdomain.replace(".", "")
    length = len(subdomain_clean)
    
    # If it is mostly hex [0-9a-f], rate it 0.5
    if re.match(r'^[0-9a-f]+$', subdomain_clean):
        return int(length * 0.5)
        
    # If it looks like base64
    if re.match(r'^[A-Za-z0-9+/=]+$', subdomain_clean):
        return int(length * 0.75)
        
    # Fallback to character length
    return length

def analyze_tunneling(
    query: str, 
    query_type: str, 
    query_rate_per_min: float, 
    unique_subdomains_cnt: int
) -> Tuple[bool, float, int]:
    """
    Heuristic analyzer for DNS Tunneling detection.
    Analyzes query structure, query type, request rate, and cache-evasion subdomains.
    Returns (is_tunneling_suspect, tunneling_score, payload_size_bytes).
    """
    if not query:
        return False, 0.0, 0
        
    extracted = tldextract.extract(query.lower())
    subdomain = extracted.subdomain
    registered_domain = f"{extracted.domain}.{extracted.suffix}"
    
    # Calculate estimated payload size
    payload_size = estimate_payload_size(query, query_type)
    
    if not subdomain:
        return False, 0.0, 0

    subdomain_len = len(subdomain)
    subdomain_entropy = calculate_entropy(subdomain)
    
    score = 0.0
    
    # 1. Subdomain Length heuristic
    if subdomain_len > 40:
        score += 0.25
    elif subdomain_len > 25:
        score += 0.15
    elif subdomain_len > config.TUNNELING_MIN_SUBDOMAIN_LEN:
        score += 0.05
        
    # 2. Entropy heuristic (indicates encrypted or compressed payload)
    if subdomain_entropy > 4.5:
        score += 0.25
    elif subdomain_entropy > config.TUNNELING_ENTROPY_THRESHOLD:
        score += 0.15
    elif subdomain_entropy > 3.5:
        score += 0.05
        
    # 3. Query Type heuristic (TXT, ANY, and CNAME are commonly abused)
    if query_type in ["TXT", "ANY"]:
        score += 0.15
    elif query_type == "CNAME" and subdomain_len > 20:
        score += 0.10
        
    # 4. Temporal Query Rate heuristic (beaconing / data transfer speed)
    if query_rate_per_min > 300.0:
        score += 0.20
    elif query_rate_per_min > config.TUNNELING_QUERY_RATE_THRESHOLD:
        score += 0.10
    elif query_rate_per_min > 30.0:
        score += 0.05
        
    # 5. Cache Bypass heuristic (many unique subdomains under same parent SLD)
    if unique_subdomains_cnt > 100:
        score += 0.20
    elif unique_subdomains_cnt > config.TUNNELING_UNIQUE_SUBDOMAINS_THRESHOLD:
        score += 0.10
    elif unique_subdomains_cnt > 5:
        score += 0.05
        
    # 6. Payload size indicator
    if payload_size > config.TUNNELING_PAYLOAD_SIZE_THRESHOLD:
        score += 0.10

    # Cap score between 0.0 and 1.0
    score = max(0.0, min(1.0, round(score, 3)))
    
    # Tunneling suspect threshold
    is_suspect = score >= 0.55
    
    return is_suspect, score, payload_size
