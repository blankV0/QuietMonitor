"""
QuietMonitor – services/compliance_service.py
─────────────────────────────────────────────
Binary compliance policy evaluator.

Compliance is distinct from risk scoring:
  - Risk scoring: weighted penalty system (produces a 0–150 score)
  - Compliance:   binary pass / fail against named policy rules

Rules evaluated:
  FIREWALL_ENABLED     – Windows Firewall must be active on all profiles  (critical)
  ANTIVIRUS_ACTIVE     – Antivirus process must be running                (critical)
  BITLOCKER_ENABLED    – System drive (C:) must be BitLocker-encrypted    (critical)
  LOCAL_ADMINS_CLEAN   – No non-default local administrator accounts      (warning)
"""

from datetime import datetime, timezone
from typing import Optional, List, Tuple

from ..schemas import ComplianceRule, MachineComplianceStatus, FleetComplianceStatus


# ── Constants ─────────────────────────────────────────────────────

# Antivirus status strings that indicate the AV is non-functional
_AV_DISABLED_STATES = {
    'disabled', 'not running', 'off', 'stopped', 'unknown',
    'not installed', 'up to date, not running', 'not monitored',
    'inactive', 'none',
}

# Normalised local-admin names that are considered "default" noise
_ADMIN_NOISE = {
    'administrator',
    'domain admins',
    'domain admins (group)',
    'administrateurs',   # French locale alias
}

# Rule definitions — order controls display order
_RULES = [
    {'rule_id': 'FIREWALL_ENABLED',   'label': 'Windows Firewall Active',          'severity': 'critical'},
    {'rule_id': 'ANTIVIRUS_ACTIVE',   'label': 'Antivirus Running',                'severity': 'critical'},
    {'rule_id': 'BITLOCKER_ENABLED',  'label': 'BitLocker Drive Encryption',       'severity': 'critical'},
    {'rule_id': 'LOCAL_ADMINS_CLEAN', 'label': 'No Unauthorised Local Admins',     'severity': 'warning'},
]


# ── Rule evaluators ───────────────────────────────────────────────

def _eval_firewall(machine) -> Tuple[Optional[bool], str]:
    if machine.firewall_enabled is None:
        return None, 'No data collected yet'
    if machine.firewall_enabled:
        return True, 'All firewall profiles are active'
    return False, 'Windows Firewall is disabled'


def _eval_antivirus(machine) -> Tuple[Optional[bool], str]:
    av = (machine.antivirus_status or '').lower().strip()
    if not av:
        return None, 'No antivirus data collected yet'
    if any(s in av for s in _AV_DISABLED_STATES):
        return False, f'Antivirus status: {machine.antivirus_status}'
    return True, f'Antivirus active — {machine.antivirus_status}'


def _eval_bitlocker(machine) -> Tuple[Optional[bool], str]:
    if machine.bitlocker_enabled is None:
        return None, 'No data collected yet'
    if machine.bitlocker_enabled:
        return True, 'System drive is encrypted (BitLocker on)'
    return False, 'System drive is NOT BitLocker-encrypted'


def _eval_local_admins(machine) -> Tuple[Optional[bool], str]:
    if machine.local_admins is None:
        return None, 'No data collected yet'
    extra = [
        a for a in machine.local_admins
        if a.lower().strip() not in _ADMIN_NOISE
    ]
    if extra:
        preview = ', '.join(extra[:3])
        suffix  = '…' if len(extra) > 3 else ''
        return False, f'Extra admins detected: {preview}{suffix}'
    return True, 'No non-default local administrator accounts'


_EVALUATORS = {
    'FIREWALL_ENABLED':   _eval_firewall,
    'ANTIVIRUS_ACTIVE':   _eval_antivirus,
    'BITLOCKER_ENABLED':  _eval_bitlocker,
    'LOCAL_ADMINS_CLEAN': _eval_local_admins,
}


# ── Public API ────────────────────────────────────────────────────

def evaluate_machine(machine) -> MachineComplianceStatus:
    """
    Evaluate all compliance rules for one Machine ORM row.

    Unknown (None) results are treated as *passing* so that machines
    that haven't sent data yet don't appear non-compliant by default.
    Only an explicit False from the evaluator counts as a failure.
    """
    rules: List[ComplianceRule] = []
    failed_rules: List[str] = []

    for rule_def in _RULES:
        rid      = rule_def['rule_id']
        evaluator = _EVALUATORS[rid]
        raw_pass, details = evaluator(machine)

        # None = no data → treat as passing (unknown, not a violation)
        is_pass = raw_pass if raw_pass is not None else True

        if raw_pass is False:
            failed_rules.append(rid)

        rules.append(ComplianceRule(
            rule_id  = rid,
            label    = rule_def['label'],
            severity = rule_def['severity'],
            passed   = is_pass,
            details  = details,
        ))

    # Determine overall severity based on the most serious failed rule
    has_critical = any(
        r for r in rules
        if not r.passed and r.severity == 'critical'
    )
    has_warning = any(
        r for r in rules
        if not r.passed and r.severity == 'warning'
    )

    overall_severity = (
        'critical'  if has_critical else
        'warning'   if has_warning  else
        'compliant'
    )

    return MachineComplianceStatus(
        machine_id   = machine.id,
        hostname     = machine.hostname,
        compliant    = len(failed_rules) == 0,
        failed_rules = failed_rules,
        severity     = overall_severity,
        rules        = rules,
        evaluated_at = datetime.now(timezone.utc),
    )


def evaluate_fleet(machines) -> FleetComplianceStatus:
    """
    Evaluate compliance for every machine in the fleet and return
    an aggregated FleetComplianceStatus.
    """
    statuses = [evaluate_machine(m) for m in machines]
    total     = len(statuses)
    n_compliant = sum(1 for s in statuses if s.compliant)
    rate = round((n_compliant / total * 100), 1) if total > 0 else 0.0

    return FleetComplianceStatus(
        total_machines = total,
        compliant      = n_compliant,
        non_compliant  = total - n_compliant,
        compliance_rate = rate,
        machines       = statuses,
    )
