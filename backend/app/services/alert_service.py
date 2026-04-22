"""
QuietMonitor – services/alert_service.py
─────────────────────────────────────────
Evaluates machine metrics after each agent update and creates Alert
records when thresholds are exceeded.

Performance alert types:
  HIGH_CPU    – CPU usage above threshold
  HIGH_RAM    – RAM usage above threshold
  LOW_DISK    – Disk usage above threshold (less free space)
  NO_AV       – Antivirus not detected / disabled

Zero Trust security alert types:
  FIREWALL_DISABLED       – Windows Firewall is turned off (critical)
  BITLOCKER_DISABLED      – System drive not encrypted (warning)
  DEFENDER_DISABLED       – Microsoft Defender real-time protection off (critical)
  RDP_ENABLED             – Remote Desktop Protocol is open (warning)
  USB_STORAGE_ENABLED     – USB mass-storage class driver enabled (warning)
  LOCAL_ADMIN_DETECTED    – Non-default local administrator accounts present (warning)
  UNKNOWN_APPS_DETECTED   – Unauthorised applications detected (warning)
"""

from datetime import datetime
from sqlalchemy.orm import Session

from ..models import Machine, Alert
from ..utils import (
    CPU_WARNING_THRESHOLD, CPU_CRITICAL_THRESHOLD,
    DISK_WARNING_THRESHOLD, DISK_CRITICAL_THRESHOLD,
    RAM_WARNING_THRESHOLD, RAM_CRITICAL_THRESHOLD,
)


def _active_alert_exists(db: Session, machine_id: int, alert_type: str) -> bool:
    """Return True if an unresolved alert of this type already exists."""
    return (
        db.query(Alert)
        .filter(
            Alert.machine_id == machine_id,
            Alert.alert_type == alert_type,
            Alert.is_resolved == False,  # noqa: E712
        )
        .first() is not None
    )


def _create_alert(db: Session, machine: Machine, alert_type: str, severity: str, message: str):
    """Insert a new alert record if one does not already exist."""
    if not _active_alert_exists(db, machine.id, alert_type):
        alert = Alert(
            machine_id=machine.id,
            alert_type=alert_type,
            severity=severity,
            message=message,
            created_at=datetime.utcnow(),
        )
        db.add(alert)
        db.commit()


def _resolve_alert(db: Session, machine_id: int, alert_type: str):
    """Mark any open alerts of the given type as resolved."""
    (
        db.query(Alert)
        .filter(
            Alert.machine_id == machine_id,
            Alert.alert_type == alert_type,
            Alert.is_resolved == False,  # noqa: E712
        )
        .update({"is_resolved": True, "resolved_at": datetime.utcnow()})
    )
    db.commit()


def evaluate_and_create_alerts(db: Session, machine: Machine):
    """
    Called after every agent update.
    Checks each threshold and either creates or resolves alerts accordingly.
    """

    # ── CPU ───────────────────────────────────────────────────────
    if machine.cpu_usage is not None:
        if machine.cpu_usage >= CPU_CRITICAL_THRESHOLD:
            _create_alert(db, machine, "HIGH_CPU", "critical",
                          f"{machine.hostname}: CPU at {machine.cpu_usage:.1f}% (critical)")
        elif machine.cpu_usage >= CPU_WARNING_THRESHOLD:
            _create_alert(db, machine, "HIGH_CPU", "warning",
                          f"{machine.hostname}: CPU at {machine.cpu_usage:.1f}% (warning)")
        else:
            _resolve_alert(db, machine.id, "HIGH_CPU")

    # ── RAM ───────────────────────────────────────────────────────
    if machine.ram_usage is not None:
        if machine.ram_usage >= RAM_CRITICAL_THRESHOLD:
            _create_alert(db, machine, "HIGH_RAM", "critical",
                          f"{machine.hostname}: RAM at {machine.ram_usage:.1f}% (critical)")
        elif machine.ram_usage >= RAM_WARNING_THRESHOLD:
            _create_alert(db, machine, "HIGH_RAM", "warning",
                          f"{machine.hostname}: RAM at {machine.ram_usage:.1f}% (warning)")
        else:
            _resolve_alert(db, machine.id, "HIGH_RAM")

    # ── DISK ──────────────────────────────────────────────────────
    if machine.disk_usage is not None:
        if machine.disk_usage >= DISK_CRITICAL_THRESHOLD:
            _create_alert(db, machine, "LOW_DISK", "critical",
                          f"{machine.hostname}: Disk at {machine.disk_usage:.1f}% (critical – nearly full)")
        elif machine.disk_usage >= DISK_WARNING_THRESHOLD:
            _create_alert(db, machine, "LOW_DISK", "warning",
                          f"{machine.hostname}: Disk at {machine.disk_usage:.1f}% (warning)")
        else:
            _resolve_alert(db, machine.id, "LOW_DISK")

    # ── ANTIVIRUS ─────────────────────────────────────────────────
    if machine.antivirus_status is not None:
        av = machine.antivirus_status.lower()
        if av in ("disabled", "not found", "unknown", "off"):
            _create_alert(db, machine, "NO_AV", "critical",
                          f"{machine.hostname}: Antivirus status is '{machine.antivirus_status}'")
        else:
            _resolve_alert(db, machine.id, "NO_AV")

    # ── FIREWALL ──────────────────────────────────────────────────
    if machine.firewall_enabled is not None:
        if machine.firewall_enabled is False:
            _create_alert(db, machine, "FIREWALL_DISABLED", "critical",
                          f"{machine.hostname}: Windows Firewall is disabled")
        else:
            _resolve_alert(db, machine.id, "FIREWALL_DISABLED")

    # ── BITLOCKER ─────────────────────────────────────────────────
    if machine.bitlocker_enabled is not None:
        if machine.bitlocker_enabled is False:
            _create_alert(db, machine, "BITLOCKER_DISABLED", "warning",
                          f"{machine.hostname}: BitLocker encryption is not enabled on system drive")
        else:
            _resolve_alert(db, machine.id, "BITLOCKER_DISABLED")

    # ── DEFENDER ──────────────────────────────────────────────────
    if machine.defender_enabled is not None:
        if machine.defender_enabled is False:
            _create_alert(db, machine, "DEFENDER_DISABLED", "critical",
                          f"{machine.hostname}: Microsoft Defender real-time protection is off")
        else:
            _resolve_alert(db, machine.id, "DEFENDER_DISABLED")

    # ── RDP ───────────────────────────────────────────────────────
    if machine.rdp_enabled is not None:
        if machine.rdp_enabled is True:
            _create_alert(db, machine, "RDP_ENABLED", "warning",
                          f"{machine.hostname}: Remote Desktop Protocol is enabled")
        else:
            _resolve_alert(db, machine.id, "RDP_ENABLED")

    # ── USB STORAGE ───────────────────────────────────────────────
    if machine.usb_storage_enabled is not None:
        if machine.usb_storage_enabled is True:
            _create_alert(db, machine, "USB_STORAGE_ENABLED", "warning",
                          f"{machine.hostname}: USB mass-storage is allowed")
        else:
            _resolve_alert(db, machine.id, "USB_STORAGE_ENABLED")

    # ── LOCAL ADMINS ──────────────────────────────────────────────
    if machine.local_admins is not None:
        noise = {"administrator", "domain admins", "domain admins (group)"}
        extra = [a for a in machine.local_admins if a.lower() not in noise]
        if extra:
            names = ", ".join(extra[:5])
            _create_alert(db, machine, "LOCAL_ADMIN_DETECTED", "warning",
                          f"{machine.hostname}: Non-default local admins detected: {names}")
        else:
            _resolve_alert(db, machine.id, "LOCAL_ADMIN_DETECTED")

    # ── UNKNOWN APPS ──────────────────────────────────────────────
    if machine.failed_checks and "UNKNOWN_APPS_DETECTED" in machine.failed_checks:
        _create_alert(db, machine, "UNKNOWN_APPS_DETECTED", "warning",
                      f"{machine.hostname}: Unauthorised applications detected")
    elif machine.installed_apps is not None:
        _resolve_alert(db, machine.id, "UNKNOWN_APPS_DETECTED")


def get_all_alerts(db: Session, unresolved_only: bool = True) -> list[Alert]:
    """Fetch alerts, optionally filtered to unresolved ones."""
    query = db.query(Alert)
    if unresolved_only:
        query = query.filter(Alert.is_resolved == False)  # noqa: E712
    return query.order_by(Alert.created_at.desc()).all()
