import os

# --- PATH CONFIGURATIONS ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_LOG_FILE = os.path.join(LOG_DIR, "dns_soc_events.json")
GEOIP_CACHE_FILE = os.path.join(LOG_DIR, "geoip_cache.json")
WHOIS_CACHE_FILE = os.path.join(LOG_DIR, "whois_cache.json")
HISTORICAL_DB_FILE = os.path.join(LOG_DIR, "historical_context.json")
VT_CACHE_FILE = os.path.join(LOG_DIR, "vt_cache.json")
VT_API_KEY = "51486511c5f2884b2050055d7509ffb3fa0081d8e5301ffb3095694eb415b22e"

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# --- OPERATION MODES ---
# If True, the agent will run in Simulation Mode, generating rich, realistic DNS events
# representing normal traffic, DGA beaconing, DNS tunneling, and typosquatting attacks
# along with realistic process contexts. If False, it will attempt real network sniffing (requires Admin).
SIMULATION_MODE = False

# Network interface to sniff DNS traffic (used if SIMULATION_MODE is False). None sniffs on all.
SNIFFER_INTERFACE = None

# --- COLLECTION SETTINGS ---
# Sniffer thread polling frequency (seconds)
SNIFFER_POLL_INTERVAL = 0.5
# Frequency (in seconds) to dump events to disk
WRITE_FREQUENCY_SECONDS = 2.0

# --- THRESHOLDS & HEURISTICS ---
# DNS Tunneling detection parameters
# (no changes here...)
TUNNELING_MIN_SUBDOMAIN_LEN = 15
TUNNELING_ENTROPY_THRESHOLD = 4.2
TUNNELING_QUERY_RATE_THRESHOLD = 100.0  # queries per minute to trigger alert
TUNNELING_UNIQUE_SUBDOMAINS_THRESHOLD = 15  # unique subdomains for same domain within window
TUNNELING_PAYLOAD_SIZE_THRESHOLD = 120  # bytes

# DGA detection parameters
DGA_ENTROPY_THRESHOLD = 3.8
DGA_CONFIDENCE_THRESHOLD = 0.75

# Typosquatting detection targets
POPULAR_BRANDS = [
    "google.com",
    "google.co.in",
    "gstatic.com",
    "googleapis.com",
    "googleusercontent.com",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "bing.com",
    "office.com",
    "office365.com",
    "paypal.com",
    "amazon.com",
    "aws.amazon.com",
    "facebook.com",
    "netflix.com",
    "github.com",
    "githubassets.com",
    "githubusercontent.com",
    "apple.com",
    "icloud.com",
    "linkedin.com",
    "yahoo.com",
    "bankofamerica.com",
    "doubleclick.net",
    "googlesyndication.com",
    "googletagmanager.com"
]

# --- LOCAL THREAT FEEDS (MOCK FEED DATABASE) ---
# In a real environment, these would be loaded from local files or threat intel feeds (OTX, Abuse.ch, etc.)
LOCAL_THREAT_FEEDS = {
    "malicious-login-paypal.xyz": {"category": "phishing", "source": "AlienVault OTX", "reputation_score": 15, "malicious_votes": 32, "suspicious_votes": 5},
    "dynamic-dns-malware.ru": {"category": "c2", "source": "Abuse.ch URLhaus", "reputation_score": 10, "malicious_votes": 68, "suspicious_votes": 12},
    "evil-c2.ru": {"category": "c2", "source": "Cisco Talos", "reputation_score": 8, "malicious_votes": 45, "suspicious_votes": 3},
    "aGVsbG8td29ybGQ.attacker-c2.ru": {"category": "c2", "source": "VirusTotal", "reputation_score": 20, "malicious_votes": 12, "suspicious_votes": 2},
    "micros0ft-login.xyz": {"category": "phishing", "source": "Spamhaus", "reputation_score": 12, "malicious_votes": 29, "suspicious_votes": 8},
    "qwe921x.biz": {"category": "malware", "source": "ThreatFeed_DGA", "reputation_score": 25, "malicious_votes": 19, "suspicious_votes": 1},
    "185.220.101.5": {"category": "tor_exit_node", "source": "TorProject", "reputation_score": 40, "malicious_votes": 85, "suspicious_votes": 24},
    
    # --- CORUNA EXPLOIT KIT & PLASMAGRID BACKDOOR FEEDS ---
    "3v5w1km5gv.xyz": {"category": "exploit_delivery", "source": "Google Threat Intel (Coruna)", "reputation_score": 95, "malicious_votes": 88, "suspicious_votes": 12},
    "cdn.uacounter.com": {"category": "exploit_delivery", "source": "Google Threat Intel (Coruna)", "reputation_score": 90, "malicious_votes": 75, "suspicious_votes": 8},
    "goodcryptocurrency.top": {"category": "exploit_delivery", "source": "Google Threat Intel (Coruna)", "reputation_score": 85, "malicious_votes": 60, "suspicious_votes": 15},
    "ztvnhmhm4zj95w3.xyz": {"category": "c2", "source": "Google Threat Intel (PLASMAGRID C2)", "reputation_score": 100, "malicious_votes": 98, "suspicious_votes": 2},
    "vvri8ocl4t3k8n6.xyz": {"category": "c2", "source": "Google Threat Intel (PLASMAGRID C2)", "reputation_score": 100, "malicious_votes": 97, "suspicious_votes": 3},
    "rlau616jc7a7f7i.xyz": {"category": "c2", "source": "Google Threat Intel (PLASMAGRID C2)", "reputation_score": 100, "malicious_votes": 96, "suspicious_votes": 4},
    "ol67el6pxg03ad7.xyz": {"category": "c2", "source": "Google Threat Intel (PLASMAGRID C2)", "reputation_score": 100, "malicious_votes": 95, "suspicious_votes": 5}
}

# --- ASSET CONTEXT ---
# Context about the local machine where the agent is running
ASSET_CONTEXT = {
    "hostname": "SOC-ANALYST-W11",
    "criticality": "HIGH",            # LOW, MEDIUM, HIGH, CRITICAL
    "business_unit": "Security Operations",
    "department": "Cyber Defense Center",
    "operating_system": "Windows 11 Enterprise",
    "os_version": "10.0.22631 Build 22631",
    "device_type": "Workstation"
}

# --- USER CONTEXT ---
USER_CONTEXT = {
    "username": "rishik_admin",
    "role": "SOC Analyst",
    "privilege": "Administrator"       # User, Administrator, System
}

# --- KAFKA CONFIGURATIONS ---
KAFKA_ENABLED = True  # Set to True to enable Kafka output
KAFKA_BOOTSTRAP_SERVERS = ["localhost:9092"]
KAFKA_TOPIC_RAW = "dns-events-raw"


