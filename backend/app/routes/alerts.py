"""
QuietMonitor – routes/alerts.py
────────────────────────────────
Alert management endpoints.

GET   /alerts              – list active (unresolved) alerts
GET   /alerts/all          – list all alerts including resolved ones
PATCH /alerts/{id}/resolve – mark an alert as resolved
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from datetime import datetime

from ..database import get_db
from ..schemas import AlertResponse, AlertResolveRequest
from ..auth import get_current_user
from ..models import Alert
from ..services.alert_service import get_all_alerts

router = APIRouter()


@router.get("/alerts", response_model=list[AlertResponse])
def list_active_alerts(
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return all currently unresolved alerts, newest first."""
    return get_all_alerts(db, unresolved_only=True)


@router.get("/alerts/all", response_model=list[AlertResponse])
def list_all_alerts(
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return all alerts (resolved and unresolved), newest first."""
    return (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )


@router.patch("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(
    alert_id: int,
    body: AlertResolveRequest,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Mark an alert as resolved (or re-open it by sending resolved=false).
    Requires any authenticated user.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert.is_resolved = body.resolved
    alert.resolved_at = datetime.utcnow() if body.resolved else None
    db.commit()
    db.refresh(alert)
    return alert
