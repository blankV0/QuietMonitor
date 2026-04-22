"""
QuietMonitor – models.py
────────────────────────
SQLAlchemy ORM models that map directly to database tables.

Tables:
  - users          : admin / viewer accounts
  - machines       : registered monitored hosts (includes Zero Trust fields)
  - machine_metrics: time-series snapshots sent by agents
  - alerts         : generated warnings / critical events

Zero Trust security fields added to Machine and MachineMetric:
  firewall_enabled, bitlocker_enabled, defender_enabled,
  rdp_enabled, usb_storage_enabled, local_admins (JSON),
  installed_apps (JSON), risk_score, trust_level, failed_checks (JSON)
"""

from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, Float,
    ForeignKey, Integer, String, Text, JSON
)
from sqlalchemy.orm import relationship
from .database import Base


# ─────────────────────────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(64), unique=True, nullable=False, index=True)
    email         = Column(String(128), unique=True, nullable=True)
    hashed_password = Column(String(256), nullable=False)

    # "admin" can create/delete; "viewer" is read-only
    role          = Column(String(16), default="viewer", nullable=False)
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────
# MACHINES
# ─────────────────────────────────────────────────────────────────
class Machine(Base):
    __tablename__ = "machines"

    id            = Column(Integer, primary_key=True, index=True)
    hostname      = Column(String(128), unique=True, nullable=False, index=True)
    ip_address    = Column(String(45), nullable=True)   # supports IPv6
    is_online     = Column(Boolean, default=False)
    last_seen     = Column(DateTime, nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)

    # Latest values cached here so the dashboard query is fast
    current_user  = Column(String(128), nullable=True)
    cpu_usage     = Column(Float, nullable=True)        # percentage 0-100
    ram_usage     = Column(Float, nullable=True)        # percentage 0-100
    disk_usage    = Column(Float, nullable=True)        # percentage 0-100
    antivirus_status = Column(String(64), nullable=True)
    last_reboot   = Column(DateTime, nullable=True)

    # ── Zero Trust / Compliance fields ───────────────────────────
    # Boolean security checks (None = not yet reported)
    firewall_enabled    = Column(Boolean, nullable=True)
    bitlocker_enabled   = Column(Boolean, nullable=True)
    defender_enabled    = Column(Boolean, nullable=True)
    rdp_enabled         = Column(Boolean, nullable=True)
    usb_storage_enabled = Column(Boolean, nullable=True)

    # JSON arrays – stored natively as JSON in SQLite
    # local_admins   : list of local administrator usernames
    # installed_apps : list of all installed application names
    # failed_checks  : list of check IDs that failed (e.g. ["FIREWALL_DISABLED"])
    local_admins    = Column(JSON, nullable=True)
    installed_apps  = Column(JSON, nullable=True)
    failed_checks   = Column(JSON, nullable=True)

    # Computed by the backend risk engine after each agent update
    risk_score  = Column(Integer, nullable=True)          # 0 = safe, 100 = critical
    trust_level = Column(String(16), nullable=True)       # "trusted"|"warning"|"critical"

    # Compliance policy evaluation result
    compliance_status   = Column(String(32), nullable=True)   # "Compliant" | "Non-Compliant"
    last_security_scan  = Column(DateTime, nullable=True)     # timestamp of last full scan

    # Relationships
    metrics          = relationship("MachineMetric", back_populates="machine",
                                    cascade="all, delete-orphan")
    alerts           = relationship("Alert", back_populates="machine",
                                    cascade="all, delete-orphan")
    security_events  = relationship("SecurityEvent", back_populates="machine",
                                    cascade="all, delete-orphan")
    snapshots        = relationship("SecuritySnapshot", back_populates="machine",
                                    cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────
# MACHINE METRICS  (historical time-series)
# ─────────────────────────────────────────────────────────────────
class MachineMetric(Base):
    __tablename__ = "machine_metrics"

    id            = Column(Integer, primary_key=True, index=True)
    machine_id    = Column(Integer, ForeignKey("machines.id"), nullable=False)
    recorded_at   = Column(DateTime, default=datetime.utcnow, index=True)

    cpu_usage     = Column(Float, nullable=True)
    ram_usage     = Column(Float, nullable=True)
    disk_usage    = Column(Float, nullable=True)
    current_user  = Column(String(128), nullable=True)
    antivirus_status = Column(String(64), nullable=True)
    last_reboot   = Column(DateTime, nullable=True)
    ip_address    = Column(String(45), nullable=True)

    # ── Zero Trust snapshot fields ────────────────────────────────
    firewall_enabled    = Column(Boolean, nullable=True)
    bitlocker_enabled   = Column(Boolean, nullable=True)
    defender_enabled    = Column(Boolean, nullable=True)
    rdp_enabled         = Column(Boolean, nullable=True)
    usb_storage_enabled = Column(Boolean, nullable=True)
    risk_score          = Column(Integer, nullable=True)
    trust_level         = Column(String(16), nullable=True)

    # Relationship back to the parent machine
    machine = relationship("Machine", back_populates="metrics")


# ─────────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id            = Column(Integer, primary_key=True, index=True)
    machine_id    = Column(Integer, ForeignKey("machines.id"), nullable=False)
    alert_type    = Column(String(64), nullable=False)   # e.g. "HIGH_CPU"
    severity      = Column(String(16), nullable=False)   # "warning" | "critical"
    message       = Column(Text, nullable=False)
    is_resolved   = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow, index=True)
    resolved_at   = Column(DateTime, nullable=True)

    # Relationship back to the parent machine
    machine = relationship("Machine", back_populates="alerts")


# ─────────────────────────────────────────────────────────────────
# SECURITY EVENTS  (per-machine audit log)
# ─────────────────────────────────────────────────────────────────
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id         = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, ForeignKey("machines.id"), nullable=False)
    event_type = Column(String(16), nullable=False)   # "CRITICAL" | "WARNING" | "INFO"
    message    = Column(Text, nullable=False)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)

    machine = relationship("Machine", back_populates="security_events")


# ─────────────────────────────────────────────────────────────────
# SECURITY SNAPSHOTS  (historical risk/compliance tracking)
# ─────────────────────────────────────────────────────────────────
class SecuritySnapshot(Base):
    __tablename__ = "security_snapshots"

    id                = Column(Integer, primary_key=True, index=True)
    machine_id        = Column(Integer, ForeignKey("machines.id"), nullable=False)
    risk_score        = Column(Integer, nullable=True)
    risk_level        = Column(String(16), nullable=True)
    compliance_status = Column(String(32), nullable=True)
    snapshot_time     = Column(DateTime, default=datetime.utcnow, index=True)

    machine = relationship("Machine", back_populates="snapshots")
