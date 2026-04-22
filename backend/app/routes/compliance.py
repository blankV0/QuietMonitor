"""
QuietMonitor – routes/compliance.py
─────────────────────────────────────
Compliance policy REST endpoints.

Routes:
  GET /compliance/status          – fleet-wide compliance summary
  GET /compliance/status/{id}     – single machine compliance detail
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..auth import get_current_user
from ..models import Machine
from ..schemas import MachineComplianceStatus, FleetComplianceStatus
from ..services.compliance_service import evaluate_machine, evaluate_fleet

router = APIRouter(tags=["compliance"])


@router.get("/compliance/status", response_model=FleetComplianceStatus)
def get_fleet_compliance(
    db:  Session = Depends(get_db),
    _          = Depends(get_current_user),
):
    """
    Return compliance evaluation results for the entire fleet.
    Machines are evaluated in real-time against stored data.
    """
    machines = db.query(Machine).order_by(Machine.hostname).all()
    return evaluate_fleet(machines)


@router.get("/compliance/status/{machine_id}", response_model=MachineComplianceStatus)
def get_machine_compliance(
    machine_id: int,
    db:  Session = Depends(get_db),
    _          = Depends(get_current_user),
):
    """
    Return detailed compliance evaluation for a single machine.
    Includes pass/fail status for each policy rule with explanatory messages.
    """
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail=f"Machine {machine_id} not found")
    return evaluate_machine(machine)
