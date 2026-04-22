"""
QuietMonitor – schemas.py
─────────────────────────
Pydantic v2 schemas used for request validation and response serialisation.
Keeping schemas separate from ORM models is a FastAPI best practice that
prevents accidental exposure of internal fields (e.g. hashed_password).

Zero Trust additions:
  AgentUpdate   – accepts the 7 new security check fields from the agent
  MachineResponse – exposes risk_score, trust_level, failed_checks + security booleans
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, field_validator


# ─────────────────────────────────────────────────────────────────
# AUTH
# ─────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


# ─────────────────────────────────────────────────────────────────
# USERS
# ─────────────────────────────────────────────────────────────────
class UserBase(BaseModel):
    username: str
    email: Optional[str] = None
    role: str = "viewer"


class UserCreate(UserBase):
    password: str


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────
# AGENT UPDATE  (payload the PowerShell agent sends)
# ─────────────────────────────────────────────────────────────────
class AgentUpdate(BaseModel):
    # ── Performance metrics ───────────────────────────────────────
    hostname: str
    ip_address: Optional[str] = None
    current_user: Optional[str] = None
    cpu_usage: Optional[float] = None
    ram_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    antivirus_status: Optional[str] = None
    last_reboot: Optional[datetime] = None

    # ── Zero Trust security checks ────────────────────────────────
    # Each field is Optional so agents that haven't been updated yet
    # still work — the risk engine treats None as "unknown".
    firewall_enabled: Optional[bool] = None        # Windows Firewall all profiles
    bitlocker_enabled: Optional[bool] = None       # BitLocker on system drive (C:)
    defender_enabled: Optional[bool] = None        # Microsoft Defender real-time protection
    rdp_enabled: Optional[bool] = None             # Remote Desktop Protocol
    usb_storage_enabled: Optional[bool] = None     # USB mass-storage class allowed
    local_admins: Optional[List[str]] = None       # List of local Administrator group members
    installed_apps: Optional[List[str]] = None     # List of installed application display names

    @field_validator("cpu_usage", "ram_usage", "disk_usage", mode="before")
    @classmethod
    def clamp_percentage(cls, v):
        """Ensure usage values stay within 0–100 range."""
        if v is not None:
            return max(0.0, min(100.0, float(v)))
        return v


# ─────────────────────────────────────────────────────────────────
# MACHINES
# ─────────────────────────────────────────────────────────────────
class MachineBase(BaseModel):
    hostname: str
    ip_address: Optional[str] = None


class MachineResponse(MachineBase):
    id: int
    is_online: bool
    last_seen: Optional[datetime]
    registered_at: datetime

    # Performance
    current_user: Optional[str]
    cpu_usage: Optional[float]
    ram_usage: Optional[float]
    disk_usage: Optional[float]
    antivirus_status: Optional[str]
    last_reboot: Optional[datetime]

    # Zero Trust security checks
    firewall_enabled: Optional[bool]
    bitlocker_enabled: Optional[bool]
    defender_enabled: Optional[bool]
    rdp_enabled: Optional[bool]
    usb_storage_enabled: Optional[bool]
    local_admins: Optional[List[str]]
    installed_apps: Optional[List[str]]

    # Risk engine output
    risk_score: Optional[int]       # 0 = fully compliant, 100 = critical
    trust_level: Optional[str]      # "trusted" | "warning" | "critical"
    failed_checks: Optional[List[str]]  # list of failed check IDs

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────
# MACHINE METRICS  (individual history entry)
# ─────────────────────────────────────────────────────────────────
class MetricResponse(BaseModel):
    id: int
    machine_id: int
    recorded_at: datetime
    cpu_usage: Optional[float]
    ram_usage: Optional[float]
    disk_usage: Optional[float]
    current_user: Optional[str]
    antivirus_status: Optional[str]
    last_reboot: Optional[datetime]
    ip_address: Optional[str]

    # Security snapshot at this point in time
    firewall_enabled: Optional[bool]
    bitlocker_enabled: Optional[bool]
    defender_enabled: Optional[bool]
    rdp_enabled: Optional[bool]
    usb_storage_enabled: Optional[bool]
    risk_score: Optional[int]
    trust_level: Optional[str]

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────────────────────────────
class AlertResponse(BaseModel):
    id: int
    machine_id: int
    alert_type: str
    severity: str
    message: str
    is_resolved: bool
    created_at: datetime
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AlertResolveRequest(BaseModel):
    resolved: bool = True
