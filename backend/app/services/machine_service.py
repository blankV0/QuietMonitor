"""
QuietMonitor – services/machine_service.py
──────────────────────────────────────────
Business logic for machine management.
Routes call these functions so the route handlers stay thin.

Zero Trust update: after each agent check-in the risk engine re-evaluates
the machine's compliance score and trust level, which are stored back on
both the Machine row and the MachineMetric snapshot.
"""

from datetime import datetime
from sqlalchemy.orm import Session

from ..models import Machine, MachineMetric
from ..schemas import AgentUpdate
from ..utils import is_machine_online, determine_status
from .alert_service import evaluate_and_create_alerts
from .risk_engine import calculate_risk


def upsert_machine(db: Session, payload: AgentUpdate) -> Machine:
    """
    Called when an agent POSTs to /agent/update.

    1. Look up the machine by hostname (create if new).
    2. Update the live performance + security fields on the Machine row.
    3. Run the risk engine → store risk_score, trust_level, failed_checks.
    4. Insert a new MachineMetric row for historical tracking.
    5. Evaluate whether any alerts should be raised.
    6. Commit and return the updated machine.
    """
    machine = db.query(Machine).filter(Machine.hostname == payload.hostname).first()

    if machine is None:
        machine = Machine(
            hostname=payload.hostname,
            registered_at=datetime.utcnow(),
        )
        db.add(machine)
        db.flush()

    # ── Performance fields ────────────────────────────────────────
    machine.ip_address       = payload.ip_address
    machine.current_user     = payload.current_user
    machine.cpu_usage        = payload.cpu_usage
    machine.ram_usage        = payload.ram_usage
    machine.disk_usage       = payload.disk_usage
    machine.antivirus_status = payload.antivirus_status
    machine.last_reboot      = payload.last_reboot
    machine.last_seen        = datetime.utcnow()
    machine.is_online        = True

    # ── Zero Trust security fields ────────────────────────────────
    if payload.firewall_enabled is not None:
        machine.firewall_enabled = payload.firewall_enabled
    if payload.bitlocker_enabled is not None:
        machine.bitlocker_enabled = payload.bitlocker_enabled
    if payload.defender_enabled is not None:
        machine.defender_enabled = payload.defender_enabled
    if payload.rdp_enabled is not None:
        machine.rdp_enabled = payload.rdp_enabled
    if payload.usb_storage_enabled is not None:
        machine.usb_storage_enabled = payload.usb_storage_enabled
    if payload.local_admins is not None:
        machine.local_admins = payload.local_admins
    if payload.installed_apps is not None:
        machine.installed_apps = payload.installed_apps

    # ── Risk engine ───────────────────────────────────────────────
    risk_score, trust_level, failed_checks = calculate_risk(
        firewall_enabled    = machine.firewall_enabled,
        defender_enabled    = machine.defender_enabled,
        bitlocker_enabled   = machine.bitlocker_enabled,
        local_admins        = machine.local_admins,
        rdp_enabled         = machine.rdp_enabled,
        usb_storage_enabled = machine.usb_storage_enabled,
        installed_apps      = machine.installed_apps,
        antivirus_status    = machine.antivirus_status,
    )
    machine.risk_score   = risk_score
    machine.trust_level  = trust_level
    machine.failed_checks = failed_checks

    # ── Historical snapshot ───────────────────────────────────────
    metric = MachineMetric(
        machine_id          = machine.id,
        recorded_at         = datetime.utcnow(),
        cpu_usage           = payload.cpu_usage,
        ram_usage           = payload.ram_usage,
        disk_usage          = payload.disk_usage,
        current_user        = payload.current_user,
        antivirus_status    = payload.antivirus_status,
        last_reboot         = payload.last_reboot,
        ip_address          = payload.ip_address,
        firewall_enabled    = machine.firewall_enabled,
        bitlocker_enabled   = machine.bitlocker_enabled,
        defender_enabled    = machine.defender_enabled,
        rdp_enabled         = machine.rdp_enabled,
        usb_storage_enabled = machine.usb_storage_enabled,
        risk_score          = risk_score,
        trust_level         = trust_level,
    )
    db.add(metric)

    db.commit()
    db.refresh(machine)

    # ── Alert conditions ──────────────────────────────────────────
    evaluate_and_create_alerts(db, machine)

    return machine


def get_all_machines(db: Session, online_only: bool = False) -> list[Machine]:
    """
    Return all registered machines.
    Optionally filter to online machines only.
    Also refreshes the `is_online` flag based on last_seen timestamp.
    """
    machines = db.query(Machine).all()

    # Refresh online status based on heartbeat time
    for m in machines:
        current_online = is_machine_online(m.last_seen)
        if m.is_online != current_online:
            m.is_online = current_online

    db.commit()

    if online_only:
        return [m for m in machines if m.is_online]
    return machines


def get_machine_by_id(db: Session, machine_id: int) -> Machine | None:
    """Return a single machine by primary key, or None."""
    return db.query(Machine).filter(Machine.id == machine_id).first()


def get_machine_history(db: Session, machine_id: int, limit: int = 100) -> list[MachineMetric]:
    """Return the most recent `limit` metric snapshots for a machine."""
    return (
        db.query(MachineMetric)
        .filter(MachineMetric.machine_id == machine_id)
        .order_by(MachineMetric.recorded_at.desc())
        .limit(limit)
        .all()
    )
