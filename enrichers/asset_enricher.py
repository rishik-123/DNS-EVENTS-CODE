import platform
import socket
import logging
from typing import Dict, Any

import config

logger = logging.getLogger(__name__)

class AssetEnricher:
    def __init__(self):
        self.static_asset = config.ASSET_CONTEXT
        self.static_user = config.USER_CONTEXT

    def enrich_context(self, event_user: str = None) -> Dict[str, Any]:
        """
        Builds user and asset context dictionaries.
        Fills missing fields dynamically using system telemetry if static values are default.
        """
        # Resolve hostname dynamically if not specified
        hostname = self.static_asset.get("hostname")
        if not hostname or hostname == "unknown":
            try:
                hostname = socket.gethostname()
            except Exception:
                hostname = "local-host"

        # Resolve OS details dynamically
        os_sys = platform.system()
        os_ver = f"{platform.release()} (Build {platform.version()})"
        
        asset_info = {
            "hostname": hostname,
            "criticality": self.static_asset.get("criticality", "MEDIUM"),
            "business_unit": self.static_asset.get("business_unit", "Corporate Operations"),
            "department": self.static_asset.get("department", "IT Department"),
            "operating_system": self.static_asset.get("operating_system") or f"{os_sys} Workstation",
            "os_version": self.static_asset.get("os_version") or os_ver,
            "device_type": self.static_asset.get("device_type", "Endpoint")
        }

        # Resolve local user context
        username = event_user if event_user and event_user != "unknown" else self.static_user.get("username")
        if not username or username == "unknown":
            try:
                username = os.getlogin()
            except Exception:
                username = "system_user"

        user_info = {
            "username": username,
            "role": self.static_user.get("role", "Corporate User"),
            "privilege": self.static_user.get("privilege", "User")
        }

        return {
            "asset_context": asset_info,
            "user_context": user_info
        }
