"""
QuietMonitor – utils.py
───────────────────────
Shared helper functions used across the backend.
Currently contains:
  - `determine_status`  : maps raw metrics to a health status string
  - `offline_threshold` : minutes of silence before a machine is marked offline
"""

from datetime import datetime, timedelta

# Number of minutes without an agent check-in before the machine is offline
OFFLINE_THRESHOLD_MINUTES = 10

# Alert thresholds
CPU_WARNING_THRESHOLD  = 80.0   # %
CPU_CRITICAL_THRESHOLD = 95.0   # %
DISK_WARNING_THRESHOLD = 85.0   # %
DISK_CRITICAL_THRESHOLD = 95.0  # %
RAM_WARNING_THRESHOLD  = 85.0   # %
RAM_CRITICAL_THRESHOLD = 95.0   # %


def determine_status(cpu: float | None, ram: float | None, disk: float | None) -> str:
    """
    Return "critical", "warning", or "healthy" based on current metrics.
    Used by the frontend to colour-code machine cards.
    """
    if cpu is None and ram is None and disk is None:
        return "unknown"

    values = [v for v in [cpu, ram, disk] if v is not None]

    if any(v >= CPU_CRITICAL_THRESHOLD for v in [cpu] if v is not None):
        return "critical"
    if any(v >= DISK_CRITICAL_THRESHOLD for v in [disk] if v is not None):
        return "critical"
    if any(v >= RAM_CRITICAL_THRESHOLD for v in [ram] if v is not None):
        return "critical"

    if any(v >= CPU_WARNING_THRESHOLD for v in [cpu] if v is not None):
        return "warning"
    if any(v >= DISK_WARNING_THRESHOLD for v in [disk] if v is not None):
        return "warning"
    if any(v >= RAM_WARNING_THRESHOLD for v in [ram] if v is not None):
        return "warning"

    return "healthy"


def is_machine_online(last_seen: datetime | None) -> bool:
    """
    Return True if the machine checked in within the offline threshold window.
    """
    if last_seen is None:
        return False
    return datetime.utcnow() - last_seen < timedelta(minutes=OFFLINE_THRESHOLD_MINUTES)
