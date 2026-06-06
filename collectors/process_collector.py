import os
import psutil
import hashlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Cache process hashes to avoid disk I/O performance penalties
_HASH_CACHE = {}

def get_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Computes MD5 and SHA-256 hashes of a file. Uses caching for performance.
    """
    if not file_path or not os.path.exists(file_path):
        return {"md5": "unknown", "sha256": "unknown"}
        
    if file_path in _HASH_CACHE:
        return _HASH_CACHE[file_path]
        
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            # Read in 64kb chunks
            for byte_block in iter(lambda: f.read(65536), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
                
        hashes = {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
        _HASH_CACHE[file_path] = hashes
        return hashes
    except Exception as e:
        logger.debug(f"Failed to calculate hash for {file_path}: {e}")
        return {"md5": "unknown", "sha256": "unknown"}

def get_process_signer(file_path: str) -> str:
    """
    Identifies the digital signature signer of the process binary.
    In a real agent, this calls Win32 APIs (e.g., CryptQueryObject) or parses PE headers.
    This provides a robust simulation based on path structure, returning real-world attributes.
    """
    if not file_path:
        return "Unsigned/Unknown"
        
    file_path_lower = file_path.lower()
    
    # Heuristics for system files on Windows
    if "system32" in file_path_lower or "syswow64" in file_path_lower:
        if file_path_lower.endswith((".exe", ".dll")):
            return "Microsoft Windows Publisher"
            
    if "program files\\google" in file_path_lower:
        return "Google LLC"
        
    if "program files\\microsoft" in file_path_lower:
        return "Microsoft Corporation"
        
    # Default fallback
    return "Unsigned/Unknown"

def get_process_metadata(pid: int) -> Dict[str, Any]:
    """
    Gathers process details, lineage, command line, user, and hashes for a given PID.
    Handles exceptions if the process has terminated (NoSuchProcess) or permissions are denied (AccessDenied).
    """
    # Default empty schema if process cannot be inspected
    empty_schema = {
        "pid": pid,
        "process_name": "unknown",
        "parent_pid": 0,
        "parent_process": "unknown",
        "command_line": "unknown",
        "exe_path": "unknown",
        "process_hash": "unknown",
        "process_sha256": "unknown",
        "signer": "unknown",
        "username": "unknown",
        "privilege": "user"
    }
    
    if pid <= 0:
        return empty_schema
        
    try:
        proc = psutil.Process(pid)
        
        # Core metadata
        name = proc.name()
        exe_path = proc.exe() if hasattr(proc, 'exe') else "unknown"
        cmdline = " ".join(proc.cmdline()) if proc.cmdline() else name
        
        # Parent context
        parent = proc.parent()
        parent_pid = parent.pid if parent else 0
        parent_name = parent.name() if parent else "unknown"
        
        # User details
        try:
            username = proc.username()
        except (psutil.AccessDenied, Exception):
            username = "unknown"
            
        # Determine privileges
        privilege = "user"
        if username:
            usr_lower = username.lower()
            if "admin" in usr_lower or "system" in usr_lower or "root" in usr_lower:
                privilege = "administrator" if "admin" in usr_lower else "system"
        
        # Hashes and signers
        hashes = get_file_hashes(exe_path)
        signer = get_process_signer(exe_path)
        
        return {
            "pid": pid,
            "process_name": name,
            "parent_pid": parent_pid,
            "parent_process": parent_name,
            "command_line": cmdline,
            "exe_path": exe_path,
            "process_hash": hashes["md5"],
            "process_sha256": hashes["sha256"],
            "signer": signer,
            "username": username,
            "privilege": privilege
        }
        
    except psutil.NoSuchProcess:
        logger.debug(f"Process with PID {pid} not found (might have terminated).")
        return empty_schema
    except psutil.AccessDenied:
        logger.debug(f"Access denied when gathering metadata for PID {pid}.")
        # Try to return basic data psutil can fetch without admin rights
        try:
            proc = psutil.Process(pid)
            return {
                "pid": pid,
                "process_name": proc.name(),
                "parent_pid": proc.parent().pid if proc.parent() else 0,
                "parent_process": proc.parent().name() if proc.parent() else "unknown",
                "command_line": "Access Denied",
                "exe_path": "Access Denied",
                "process_hash": "Access Denied",
                "process_sha256": "Access Denied",
                "signer": "Access Denied",
                "username": "Access Denied",
                "privilege": "unknown"
            }
        except Exception:
            return empty_schema
    except Exception as e:
        logger.error(f"Unexpected error retrieving process metadata for PID {pid}: {e}")
        return empty_schema
