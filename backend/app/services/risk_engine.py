"""
QuietMonitor – services/risk_engine.py
───────────────────────────────────────
Zero Trust risk scoring engine.

Each security check that fails adds a penalty to the machine's risk score
(0 = fully compliant, 100 = maximum risk).  After summing the penalties the
score is clamped to [0, 100] and classified into a trust level:

    0 – 30  →  "trusted"   (green)
   31 – 60  →  "warning"   (yellow)
   61 – 100 →  "critical"  (red)

The engine also returns a list of human-readable check IDs for every violation
so that the frontend can render exactly which controls failed.
"""

from __future__ import annotations
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Risk weights (penalty points per failed control)
# Weights match the product specification:
#   Firewall disabled      +25
#   Defender disabled      +30
#   BitLocker disabled     +25
#   Local admin present    +20
#   RDP enabled            +15
#   Unknown software       +35  (flat penalty when any unknown app detected)
# ─────────────────────────────────────────────────────────────────────────────
WEIGHT_FIREWALL_DISABLED   = 25   # Network perimeter collapsed
WEIGHT_DEFENDER_DISABLED   = 30   # AV/EDR absent → highest penalty
WEIGHT_BITLOCKER_DISABLED  = 25   # Data-at-rest not encrypted
WEIGHT_LOCAL_ADMIN         = 20   # Elevated local accounts
WEIGHT_RDP_ENABLED         = 15   # Remote attack surface open
WEIGHT_UNKNOWN_APP         = 35   # Unauthorised software detected (flat)

# ─────────────────────────────────────────────────────────────────────────────
# Application allow-list
# Any installed app whose lowercase display-name contains one of these
# substrings is considered approved.  Everything else is flagged.
# ─────────────────────────────────────────────────────────────────────────────
APPROVED_KEYWORDS: set[str] = {
    # Microsoft ecosystem
    "microsoft", "windows", "office", ".net", "visual c++", "visual studio",
    "directx", "xbox",
    # Browsers
    "google chrome", "mozilla firefox", "microsoft edge",
    # Security tools
    "defender", "malwarebytes", "crowdstrike", "sentinelone", "carbon black",
    "bitdefender", "symantec", "mcafee", "trend micro",
    # Productivity / dev
    "7-zip", "notepad++", "visual studio code", "git", "github desktop",
    "python", "node.js", "java", "jdk", "jre", "docker",
    # Communications
    "zoom", "teams", "slack", "webex", "skype",
    # Hardware / drivers
    "nvidia", "amd", "intel", "realtek", "logitech", "dell", "hp", "lenovo",
    "synaptics", "brother", "epson", "canon",
    # Remote management (approved)
    "sccm", "intune", "tanium", "ivanti",
    # Other common enterprise
    "adobe acrobat", "adobe reader", "vlc", "winrar", "putty",
    "wireshark", "powershell", "azure cli",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_approved(app_name: str) -> bool:
    """Return True if an application name matches any approved keyword."""
    lower = app_name.lower()
    return any(kw in lower for kw in APPROVED_KEYWORDS)


def _classify(score: int) -> str:
    """Map clamped 0-100 score to a trust level label."""
    if score <= 30:
        return "trusted"
    elif score <= 60:
        return "warning"
    return "critical"


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk(
    *,
    firewall_enabled: Optional[bool],
    defender_enabled: Optional[bool],
    bitlocker_enabled: Optional[bool],
    local_admins: Optional[list[str]],
    rdp_enabled: Optional[bool],
    usb_storage_enabled: Optional[bool],
    installed_apps: Optional[list[str]],
    antivirus_status: Optional[str],
) -> tuple[int, str, list[str]]:
    """
    Compute risk score, trust level, and the list of failed check IDs.

    Parameters
    ----------
    All keyword-only; pass the values directly from the Machine ORM row or
    the AgentUpdate payload.

    Returns
    -------
    (risk_score: int, trust_level: str, failed_checks: list[str])
    """
    score: int = 0
    failed: list[str] = []

    # ── 1. Windows Firewall ─────────────────────────────────────────────────
    if firewall_enabled is False:
        score += WEIGHT_FIREWALL_DISABLED
        failed.append("FIREWALL_DISABLED")

    # ── 2. Microsoft Defender / Antivirus ───────────────────────────────────
    defender_off = defender_enabled is False
    av_off = antivirus_status is not None and antivirus_status.lower() in (
        "disabled", "inactive", "not running", "off", "unknown"
    )
    if defender_off or av_off:
        score += WEIGHT_DEFENDER_DISABLED
        failed.append("DEFENDER_DISABLED")

    # ── 3. BitLocker disk encryption ────────────────────────────────────────
    if bitlocker_enabled is False:
        score += WEIGHT_BITLOCKER_DISABLED
        failed.append("BITLOCKER_DISABLED")

    # ── 4. Privileged local accounts ────────────────────────────────────────
    # Flag if any non-default accounts are in the Administrators group.
    # "Administrator" (built-in, often disabled) and "Domain Admins" are
    # expected; any other name is suspicious.
    if local_admins:
        noise = {"administrator", "domain admins", "domain admins (group)"}
        extra = [a for a in local_admins if a.lower() not in noise]
        if extra:
            score += WEIGHT_LOCAL_ADMIN
            failed.append("LOCAL_ADMIN_DETECTED")

    # ── 5. Remote Desktop Protocol ──────────────────────────────────────────
    if rdp_enabled is True:
        score += WEIGHT_RDP_ENABLED
        failed.append("RDP_ENABLED")

    # ── 6. USB mass storage (informational – not in primary spec) ────────────
    # USB is tracked but does not contribute to the primary score so that the
    # 6-check spec weights sum predictably.  The failed_checks list still
    # records it so the UI can surface it.
    if usb_storage_enabled is True:
        failed.append("USB_STORAGE_ENABLED")

    # ── 7. Unauthorised applications ────────────────────────────────────────
    # Flat penalty: any presence of unknown software triggers the full +35.
    # The individual app names are preserved in failed_checks detail.
    if installed_apps:
        unknown = [a for a in installed_apps if not _is_approved(a)]
        if unknown:
            score += WEIGHT_UNKNOWN_APP
            failed.append("UNKNOWN_APPS_DETECTED")

    # ── Clamp and classify ───────────────────────────────────────────────────
    risk_score = max(0, min(100, score))
    trust_level = _classify(risk_score)

    return risk_score, trust_level, failed
