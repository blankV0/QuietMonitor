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

from ..database import get_db
from ..schemas import AgentUpdate, MachineResponse, MetricResponse
from ..auth import get_current_user
from ..services.machine_service import (
    upsert_machine,
    get_all_machines,
    get_machine_by_id,
    get_machine_history,
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
