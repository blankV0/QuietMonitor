"""
QuietMonitor – routes/security.py
───────────────────────────────────
Security-focused endpoints that wrap responses in the
standard { "success": true, "data": ... } envelope.

Endpoints:
  GET /security/risk          – All machines with full risk + compliance detail
  GET /machine/{id}/security  – Single machine deep security view
  GET /events/recent          – Most-recent SecurityEvent rows (default 50)
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Machine, SecurityEvent, SecuritySnapshot
from ..services.risk_engine import calculate_risk
from ..services.compliance_service import evaluate_compliance
from ..schemas import ApiResponse, MachineSecurityDetail, SecurityEventResponse
from ..auth import get_current_user

router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────

def _build_machine_detail(m: Machine) -> MachineSecurityDetail:
    """Convert a Machine ORM row → MachineSecurityDetail schema."""
    risk_info = calculate_risk(m)
    comp_info = evaluate_compliance(m)

    checks = [
        {"check_id": c.check_id, "passed": c.passed,
         "severity": c.severity, "description": c.description}
        for c in comp_info.checks
    ]

    return MachineSecurityDetail(
        machine_id         = m.id,
        hostname           = m.hostname,
        ip_address         = m.ip_address,
        is_online          = m.is_online,
        risk_score         = m.risk_score,
        trust_level        = m.trust_level,
        compliance_status  = m.compliance_status,
        last_security_scan = m.last_security_scan,
        failed_checks      = m.failed_checks or [],
        checks             = checks,
        firewall_enabled   = m.firewall_enabled,
        defender_enabled   = m.defender_enabled,
        bitlocker_enabled  = m.bitlocker_enabled,
        rdp_enabled        = m.rdp_enabled,
        usb_storage_enabled= m.usb_storage_enabled,
        local_admins       = m.local_admins or [],
    )


# ── GET /security/risk ────────────────────────────────────────────

@router.get("/security/risk", tags=["Security"])
def get_fleet_security_risk(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    Return risk + compliance detail for every registered machine,
    sorted by risk_score descending (highest risk first).
    """
    machines = (
        db.query(Machine)
        .order_by(Machine.risk_score.desc().nullslast())
        .all()
    )
    data = [_build_machine_detail(m) for m in machines]
    return ApiResponse(success=True, data=[d.model_dump() for d in data])


# ── GET /machine/{id}/security ────────────────────────────────────

@router.get("/machine/{machine_id}/security", tags=["Security"])
def get_machine_security(
    machine_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    """Full security detail for a single machine."""
    m = db.query(Machine).filter(Machine.id == machine_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Machine not found")
    detail = _build_machine_detail(m)
    return ApiResponse(success=True, data=detail.model_dump())


# ── GET /events/recent ────────────────────────────────────────────

@router.get("/events/recent", tags=["Security"])
def get_recent_events(
    limit: int = Query(default=50, ge=1, le=500),
    event_type: Optional[str] = Query(default=None, description="Filter: CRITICAL | WARNING | INFO"),
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    """
    Returns the most recent SecurityEvent rows, newest first.
    Optionally filter by event_type (CRITICAL / WARNING / INFO).
    Each row includes the machine hostname for display convenience.
    """
    q = db.query(SecurityEvent)
    if event_type:
        q = q.filter(SecurityEvent.event_type == event_type.upper())

    rows = q.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()

    # Resolve hostnames in one pass via the already-loaded relationship
    data = [
        SecurityEventResponse(
            id         = e.id,
            machine_id = e.machine_id,
            event_type = e.event_type,
            message    = e.message,
            timestamp  = e.timestamp,
            hostname   = e.machine.hostname if e.machine else None,
        ).model_dump()
        for e in rows
    ]
    return ApiResponse(success=True, data=data)
