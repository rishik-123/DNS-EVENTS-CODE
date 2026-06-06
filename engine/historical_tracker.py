import os
import json
import time
import logging
import threading
import tldextract
from datetime import datetime, timedelta
from typing import Dict, Any, List

import config

logger = logging.getLogger(__name__)

class HistoricalTracker:
    def __init__(self):
        self.db_path = config.HISTORICAL_DB_FILE
        self.lock = threading.Lock()
        
        # Structure:
        # {
        #   "domains": {
        #      "example.com": {
        #         "first_seen": "2026-06-04T20:00:00Z",
        #         "last_seen": "2026-06-04T20:05:00Z",
        #         "frequency": 12,
        #         "subdomains": ["www", "mail", "blog"],
        #         "timestamps": [1780512345.0, 1780512645.0]
        #      }
        #   }
        # }
        self.db = self._load_db()
        self.last_save_time = time.time()

    def _load_db(self) -> Dict[str, Any]:
        """Loads historical database from disk."""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                    if "domains" not in data:
                        data = {"domains": {}}
                    return data
            except Exception as e:
                logger.error(f"Error loading historical database: {e}")
        return {"domains": {}}

    def save_db(self):
        """Saves historical database to disk."""
        with self.lock:
            try:
                # Cleanup timestamps to keep file size reasonable
                now = time.time()
                for dom_info in self.db["domains"].values():
                    # Keep only timestamps from the last 5 minutes (300 seconds) for rate calculation
                    dom_info["timestamps"] = [ts for ts in dom_info.get("timestamps", []) if now - ts < 300]
                
                with open(self.db_path, 'w') as f:
                    json.dump(self.db, f, indent=4)
                self.last_save_time = now
            except Exception as e:
                logger.error(f"Error saving historical database: {e}")

    def update_and_get_stats(self, query: str, timestamp_str: str) -> Dict[str, Any]:
        """
        Updates the history for a given query and calculates temporal statistics.
        Returns a dictionary of historical and rate attributes.
        """
        if not query:
            return {
                "first_seen": timestamp_str,
                "last_seen": timestamp_str,
                "frequency": 1,
                "unique_subdomains_count": 0,
                "query_rate_per_minute": 0.0
            }

        extracted = tldextract.extract(query.lower())
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        subdomain = extracted.subdomain

        if not extracted.domain:
            # Handle cases where parsing fails
            registered_domain = query.lower()
            subdomain = ""

        now_unix = time.time()
        
        with self.lock:
            domains = self.db["domains"]
            
            if registered_domain not in domains:
                # Brand new domain seen by the system
                domains[registered_domain] = {
                    "first_seen": timestamp_str,
                    "last_seen": timestamp_str,
                    "frequency": 1,
                    "subdomains": [subdomain] if subdomain else [],
                    "timestamps": [now_unix]
                }
            else:
                entry = domains[registered_domain]
                entry["last_seen"] = timestamp_str
                entry["frequency"] += 1
                
                # Update subdomains list
                if subdomain and subdomain not in entry["subdomains"]:
                    entry["subdomains"].append(subdomain)
                    
                # Append current query timestamp
                entry["timestamps"].append(now_unix)

            # Retrieve info
            entry = domains[registered_domain]
            first_seen = entry["first_seen"]
            last_seen = entry["last_seen"]
            frequency = entry["frequency"]
            unique_subdomains_count = len(entry["subdomains"])
            
            # Calculate rolling rate per minute based on the last 1 minute (60 seconds)
            # Find how many timestamps fall in the last 60 seconds
            recent_timestamps = [ts for ts in entry["timestamps"] if now_unix - ts <= 60.0]
            query_rate_per_minute = float(len(recent_timestamps))

        # Periodically auto-save to disk (every 10 seconds or if requested)
        if time.time() - self.last_save_time > 10.0:
            threading.Thread(target=self.save_db, daemon=True).start()

        return {
            "first_seen": first_seen,
            "last_seen": last_seen,
            "frequency": frequency,
            "unique_subdomains_count": unique_subdomains_count,
            "query_rate_per_minute": query_rate_per_minute
        }
