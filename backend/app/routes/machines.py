"""
QuietMonitor – routes/machines.py
──────────────────────────────────
REST endpoints related to machine management.

GET  /machines              – list all machines (with optional ?online_only=true)
GET  /machines/{id}         – full detail for one machine
GET  /machines/{id}/history – recent metric history for one machine
POST /agent/update          – agent heartbeat / data push (no auth required)
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from collections import Counter

from ..database import get_db
from ..schemas import AgentUpdate, MachineResponse, MetricResponse, RiskDetail, FleetRiskSummary, CheckDetail
from ..auth import get_current_user
from ..services.machine_service import (
    upsert_machine,
    get_all_machines,
    get_machine_by_id,
    get_machine_history,
)
from ..services.risk_engine import (
    calculate_risk,
    WEIGHT_FIREWALL_DISABLED, WEIGHT_DEFENDER_DISABLED, WEIGHT_BITLOCKER_DISABLED,
    WEIGHT_LOCAL_ADMIN, WEIGHT_RDP_ENABLED, WEIGHT_UNKNOWN_APP,
)

router = APIRouter()


# ── Agent heartbeat ───────────────────────────────────────────────
@router.post("/agent/update", response_model=MachineResponse, status_code=status.HTTP_200_OK)
def agent_update(payload: AgentUpdate, db: Session = Depends(get_db)):
    """
    Unauthenticated endpoint called by the PowerShell agent every 5 minutes.
    Accepts machine health data, updates the database, and triggers alert evaluation.
    """
    return upsert_machine(db, payload)


# ── List all machines ─────────────────────────────────────────────
@router.get("/machines", response_model=list[MachineResponse])
def list_machines(
    online_only: bool = Query(False, description="Return only currently online machines"),
    search: str = Query("", description="Filter machines by hostname (case-insensitive)"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return every registered machine.
    Supports optional ?online_only=true and ?search=<hostname_fragment> filters.
    """
    machines = get_all_machines(db, online_only=online_only)

    if search:
        machines = [m for m in machines if search.lower() in m.hostname.lower()]

    return machines


# ── Risk helpers (must be defined before {machine_id} wildcard routes) ───────
def _build_risk_detail(machine) -> RiskDetail:
    """Build a RiskDetail object from an ORM Machine row."""
    noise = {"administrator", "domain admins", "domain admins (group)"}
    admins = machine.local_admins or []
    extra_admins = [a for a in admins if a.lower() not in noise]
    apps = machine.installed_apps or []

    checks = [
        CheckDetail(
            check_id="FIREWALL_DISABLED",
            label="Windows Firewall",
            weight=WEIGHT_FIREWALL_DISABLED,
            passed=machine.firewall_enabled is not False,
            value=str(machine.firewall_enabled) if machine.firewall_enabled is not None else None,
        ),
        CheckDetail(
            check_id="DEFENDER_DISABLED",
            label="Microsoft Defender",
            weight=WEIGHT_DEFENDER_DISABLED,
            passed=machine.defender_enabled is not False,
            value=str(machine.defender_enabled) if machine.defender_enabled is not None else None,
        ),
        CheckDetail(
            check_id="BITLOCKER_DISABLED",
            label="BitLocker Encryption",
            weight=WEIGHT_BITLOCKER_DISABLED,
            passed=machine.bitlocker_enabled is not False,
            value=str(machine.bitlocker_enabled) if machine.bitlocker_enabled is not None else None,
        ),
        CheckDetail(
            check_id="LOCAL_ADMIN_DETECTED",
            label="Local Admin Accounts",
            weight=WEIGHT_LOCAL_ADMIN,
            passed=len(extra_admins) == 0,
            value=f"{len(extra_admins)} extra account(s)" if extra_admins else "none",
        ),
        CheckDetail(
            check_id="RDP_ENABLED",
            label="Remote Desktop (RDP)",
            weight=WEIGHT_RDP_ENABLED,
            passed=machine.rdp_enabled is not True,
            value=str(machine.rdp_enabled) if machine.rdp_enabled is not None else None,
        ),
        CheckDetail(
            check_id="UNKNOWN_APPS_DETECTED",
            label="Unknown Software",
            weight=WEIGHT_UNKNOWN_APP,
            passed="UNKNOWN_APPS_DETECTED" not in (machine.failed_checks or []),
            value=f"{len(apps)} apps scanned" if apps else None,
        ),
    ]

    risk_level = (machine.trust_level or "unscored").capitalize()
    return RiskDetail(
        machine_id=machine.id,
        hostname=machine.hostname,
        risk_score=machine.risk_score or 0,
        risk_level=risk_level,
        failed_checks=machine.failed_checks or [],
        checks=checks,
    )


# ── Fleet-wide risk summary (literal path — must come before {machine_id}) ───
@router.get("/machines/risk-summary", response_model=FleetRiskSummary)
def fleet_risk_summary(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Aggregate risk statistics across the entire monitored fleet.

    Returns counts per trust level, average risk score, the most common
    failing check, and a per-machine RiskDetail breakdown.
    """
    machines = get_all_machines(db)

    trusted = warning = critical = unscored = 0
    scores: list[int] = []
    failure_counter: Counter = Counter()
    details: list[RiskDetail] = []

    for m in machines:
        details.append(_build_risk_detail(m))
        if m.risk_score is None or m.trust_level is None:
            unscored += 1
        else:
            scores.append(m.risk_score)
            lvl = m.trust_level
            if lvl == "trusted":
                trusted += 1
            elif lvl == "warning":
                warning += 1
            else:
                critical += 1
        for chk in (m.failed_checks or []):
            failure_counter[chk] += 1

    avg = round(sum(scores) / len(scores), 1) if scores else None
    most_common = failure_counter.most_common(1)[0][0] if failure_counter else None

    return FleetRiskSummary(
        total_machines=len(machines),
        trusted=trusted,
        warning=warning,
        critical=critical,
        unscored=unscored,
        avg_risk_score=avg,
        most_common_failure=most_common,
        machines=details,
    )


# ── Single machine detail ─────────────────────────────────────────
@router.get("/machines/{machine_id}", response_model=MachineResponse)
def get_machine(
    machine_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return full details for a single machine by its ID."""
    machine = get_machine_by_id(db, machine_id)
    if not machine:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found")
    return machine


# ── Metric history ────────────────────────────────────────────────
@router.get("/machines/{machine_id}/history", response_model=list[MetricResponse])
def machine_history(
    machine_id: int,
    limit: int = Query(100, ge=1, le=1000, description="Max number of records to return"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return the most recent metric snapshots for a machine (default last 100)."""
    machine = get_machine_by_id(db, machine_id)
    if not machine:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found")
    return get_machine_history(db, machine_id, limit=limit)


# ── Risk breakdown for a single machine ──────────────────────────
@router.get("/machines/{machine_id}/risk", response_model=RiskDetail)
def machine_risk(
    machine_id: int,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Return the full risk engine breakdown for a single machine.

    Includes risk_score (0-100), risk_level (Trusted/Warning/Critical),
    failed_checks list, and a per-check detail with weight and raw value.
    """
    machine = get_machine_by_id(db, machine_id)
    if not machine:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Machine not found")
    return _build_risk_detail(machine)

