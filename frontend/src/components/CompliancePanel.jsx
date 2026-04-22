/**
 * QuietMonitor – components/CompliancePanel.jsx
 * ───────────────────────────────────────────────
 * Zero Trust security posture panel.
 *
 * Renders a 7-row compliance checklist showing pass / fail for each
 * security control, a risk score gauge, and the machine's trust level.
 *
 * Props:
 *   machine  – machine object from the API (MachineResponse)
 */

import React from 'react'
import {
  ShieldCheck, ShieldAlert, ShieldOff,
  Lock, Unlock, Flame, Monitor, Usb, Users, Package,
  CheckCircle2, XCircle, HelpCircle,
} from 'lucide-react'

// ── Trust level meta ──────────────────────────────────────────────
const TRUST_META = {
  trusted:  { color: '#22c55e', bg: 'rgba(34,197,94,0.12)',   label: 'TRUSTED',  Icon: ShieldCheck },
  warning:  { color: '#eab308', bg: 'rgba(234,179,8,0.12)',   label: 'WARNING',  Icon: ShieldAlert },
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)',   label: 'CRITICAL', Icon: ShieldOff   },
}

// ── Security check definitions ────────────────────────────────────
// Each check maps a check-id (matches failed_checks from backend)
// to display metadata and the field on the machine object.
const CHECKS = [
  {
    id:       'FIREWALL_DISABLED',
    label:    'Windows Firewall',
    Icon:     Flame,
    pass:     (m) => m.firewall_enabled === true,
    fail:     (m) => m.firewall_enabled === false,
    passMsg:  'All firewall profiles enabled',
    failMsg:  'Windows Firewall is disabled',
  },
  {
    id:       'DEFENDER_DISABLED',
    label:    'Microsoft Defender',
    Icon:     ShieldCheck,
    pass:     (m) => m.defender_enabled === true,
    fail:     (m) => m.defender_enabled === false,
    passMsg:  'Real-time protection active',
    failMsg:  'Defender real-time protection is off',
  },
  {
    id:       'BITLOCKER_DISABLED',
    label:    'BitLocker Encryption',
    Icon:     Lock,
    pass:     (m) => m.bitlocker_enabled === true,
    fail:     (m) => m.bitlocker_enabled === false,
    passMsg:  'System drive is encrypted',
    failMsg:  'System drive is not encrypted',
  },
  {
    id:       'LOCAL_ADMIN_DETECTED',
    label:    'Local Administrator Accounts',
    Icon:     Users,
    pass:     (m) => {
      if (!m.local_admins) return null
      const noise = ['administrator', 'domain admins', 'domain admins (group)']
      return m.local_admins.filter(a => !noise.includes(a.toLowerCase())).length === 0
    },
    fail:     (m) => {
      if (!m.local_admins) return false
      const noise = ['administrator', 'domain admins', 'domain admins (group)']
      return m.local_admins.filter(a => !noise.includes(a.toLowerCase())).length > 0
    },
    passMsg:  'No non-default local admins',
    failMsg:  (m) => {
      const noise = ['administrator', 'domain admins', 'domain admins (group)']
      const extra = (m.local_admins || []).filter(a => !noise.includes(a.toLowerCase()))
      return `Extra admins: ${extra.slice(0, 3).join(', ')}${extra.length > 3 ? '…' : ''}`
    },
  },
  {
    id:       'RDP_ENABLED',
    label:    'Remote Desktop (RDP)',
    Icon:     Monitor,
    pass:     (m) => m.rdp_enabled === false,
    fail:     (m) => m.rdp_enabled === true,
    passMsg:  'RDP is disabled',
    failMsg:  'RDP is enabled — remote attack surface exposed',
  },
  {
    id:       'USB_STORAGE_ENABLED',
    label:    'USB Mass Storage',
    Icon:     Usb,
    pass:     (m) => m.usb_storage_enabled === false,
    fail:     (m) => m.usb_storage_enabled === true,
    passMsg:  'USB storage class driver is blocked',
    failMsg:  'USB mass storage is allowed',
  },
  {
    id:       'UNKNOWN_APPS_DETECTED',
    label:    'Application Inventory',
    Icon:     Package,
    pass:     (m) => m.installed_apps != null && !(m.failed_checks || []).includes('UNKNOWN_APPS_DETECTED'),
    fail:     (m) => (m.failed_checks || []).includes('UNKNOWN_APPS_DETECTED'),
    passMsg:  'All installed applications are approved',
    failMsg:  'Unauthorised applications detected',
  },
]

// ── Risk score gauge ──────────────────────────────────────────────
function RiskGauge({ score }) {
  if (score == null) return null
  const color =
    score <= 30 ? '#22c55e' :
    score <= 60 ? '#eab308' :
    '#ef4444'

  // SVG arc gauge (semicircle)
  const r   = 40
  const cx  = 60
  const cy  = 60
  const arc = Math.PI   // half-circle (radians)
  const startAngle = Math.PI          // left
  const endAngle   = 0                // right
  // Sweep: score 0→100 maps startAngle→endAngle
  const scoreAngle = startAngle - (score / 100) * arc

  const toXY = (angle, radius) => [
    cx + radius * Math.cos(angle),
    cy + radius * Math.sin(angle),
  ]
  const [sx, sy] = toXY(startAngle, r)
  const [ex, ey] = toXY(scoreAngle, r)
  const largeArc = (startAngle - scoreAngle) > Math.PI ? 1 : 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.25rem' }}>
      <svg width="120" height="70" viewBox="0 0 120 70">
        {/* Background track */}
        <path
          d={`M ${toXY(startAngle, r)[0]} ${toXY(startAngle, r)[1]} A ${r} ${r} 0 0 0 ${toXY(endAngle, r)[0]} ${toXY(endAngle, r)[1]}`}
          fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round"
        />
        {/* Score fill */}
        {score > 0 && (
          <path
            d={`M ${sx} ${sy} A ${r} ${r} 0 ${largeArc} 0 ${ex} ${ey}`}
            fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          />
        )}
        {/* Score label */}
        <text x={cx} y={cy - 4} textAnchor="middle" fill={color} fontSize="20" fontWeight="700">
          {score}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="var(--text-muted)" fontSize="9">
          / 100
        </text>
      </svg>
      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        Risk Score
      </span>
    </div>
  )
}

// ── Single check row ──────────────────────────────────────────────
function CheckRow({ check, machine }) {
  const passed   = check.pass(machine)
  const failed   = check.fail(machine)
  const unknown  = passed == null && !failed

  const statusColor =
    failed  ? '#ef4444' :
    passed  ? '#22c55e' :
    'var(--text-muted)'

  const StatusIcon =
    failed  ? XCircle :
    passed  ? CheckCircle2 :
    HelpCircle

  const msg =
    failed
      ? (typeof check.failMsg === 'function' ? check.failMsg(machine) : check.failMsg)
      : passed
        ? check.passMsg
        : 'Data not available'

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: '0.85rem',
      padding: '0.65rem 0', borderBottom: '1px solid var(--border)',
    }}>
      <check.Icon size={16} style={{ color: statusColor, flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
          {check.label}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
          {msg}
        </div>
      </div>
      <StatusIcon size={18} style={{ color: statusColor, flexShrink: 0 }} />
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────
export default function CompliancePanel({ machine }) {
  const trustLevel = machine.trust_level || 'unknown'
  const meta       = TRUST_META[trustLevel] || {
    color: 'var(--text-muted)', bg: 'transparent', label: 'UNKNOWN', Icon: ShieldCheck,
  }
  const { Icon: TrustIcon } = meta

  const passCount = CHECKS.filter((c) => c.pass(machine)).length
  const failCount = CHECKS.filter((c) => c.fail(machine)).length

  return (
    <div style={{
      background: 'var(--bg-card)', border: `1px solid var(--border)`,
      borderRadius: 'var(--radius)', padding: '1.25rem',
      borderTop: `3px solid ${meta.color}`,
    }}>
      {/* Panel header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1rem' }}>
        <div>
          <p style={{ fontSize: '0.82rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
            Zero Trust Compliance
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
              padding: '0.3rem 0.75rem', borderRadius: '999px',
              background: meta.bg, color: meta.color,
              fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.06em',
            }}>
              <TrustIcon size={13} />
              {meta.label}
            </span>
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {passCount} passed · {failCount} failed
            </span>
          </div>
        </div>
        <RiskGauge score={machine.risk_score} />
      </div>

      {/* Check rows */}
      {CHECKS.map((check) => (
        <CheckRow key={check.id} check={check} machine={machine} />
      ))}

      {/* Local admins list (if any non-default) */}
      {machine.local_admins && machine.local_admins.length > 0 && (
        <div style={{ marginTop: '0.75rem', padding: '0.6rem 0.8rem', background: 'rgba(239,68,68,0.06)', borderRadius: '6px', fontSize: '0.75rem' }}>
          <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Local admins: </span>
          <span style={{ color: 'var(--text-secondary)' }}>{machine.local_admins.join(', ')}</span>
        </div>
      )}
    </div>
  )
}
