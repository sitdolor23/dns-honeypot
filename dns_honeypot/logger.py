import json
import time

from .config import LOG_FILE

# Builds one log entry from the event type and any extra fields passed in,
# then appends it as a single JSON line to the log file.
def log_event(event_type, **fields):
    entry = {
        "eventid": event_type,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()),
        **fields,
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
