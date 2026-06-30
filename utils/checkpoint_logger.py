import os
import datetime
import json
import threading
import config

# Create lock for thread-safe file writes
_log_lock = threading.Lock()

def log_checkpoint(checkpoint_id: str, message: str, details: dict = None):
    """
    Appends a checkpoint telemetry log entry to checkpoints.log.
    Format: ISO_TIMESTAMP [CHECKPOINT_ID] message | Details: JSON_STRING
    """
    timestamp = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Construct log entry
    log_entry = f"{timestamp} [{checkpoint_id}] {message}"
    if details:
        log_entry += f" | Details: {json.dumps(details)}"
    log_entry += "\n"
    
    # Ensure logs folder exists
    try:
        os.makedirs(config.LOG_DIR, exist_ok=True)
    except Exception:
        pass
        
    log_file_path = os.path.join(config.LOG_DIR, "checkpoints.log")
    
    # Thread-safe write to checkpoints.log
    with _log_lock:
        try:
            with open(log_file_path, "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            # Fallback output if file writing fails
            print(f"[CHECKPOINT LOGGER ERROR] {e}")
