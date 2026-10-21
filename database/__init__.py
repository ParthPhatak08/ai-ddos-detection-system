"""Database package initialization."""
from .db import (
    init_db,
    log_threat_event,
    log_telemetry_snapshot,
    get_recent_threats,
    get_threat_by_id,
    get_system_statistics,
    clear_all_events
)
