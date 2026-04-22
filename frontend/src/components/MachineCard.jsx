/**
 * QuietMonitor – components/MachineCard.jsx
 * ───────────────────────────────────────────
 * Dashboard card for a single monitored machine.
 *
 * Zero Trust layout:
 *   - Accent bar at top uses trust_level colour
 *   - Trust badge + risk score
 *   - Failed check chips (up to 3)
 *   - CPU / RAM / Disk metric bars
 *
 * Props:
 *   machine  – MachineResponse from the API
 *   onClick  – () => void
 */

import React from 'react'
import {
  Cpu, HardDrive, MemoryStick, Wifi, WifiOff,
  User, ShieldCheck, ShieldAlert, ShieldOff,
} from 'lucide-react'

// ── Trust level meta ──────────────────────────────────────────────
const TRUST_META = {
  trusted:  { color: '#22c55e', label: 'Trusted',  glow: '0 0 0 2px rgba(34,197,94,0.25)',  Icon: ShieldCheck },
  warning:  { color: '#eab308', label: 'Warning',  glow: '0 0 0 2px rgba(234,179,8,0.25)',  Icon: ShieldAlert },
  critical: { color: '#ef4444', label: 'Critical', glow: '0 0 0 2px rgba(239,68,68,0.25)',  Icon: ShieldOff   },
  unknown:  { color: 'var(--text-muted)', label: 'Unknown', glow: 'none', Icon: ShieldCheck },
}

// ── Metric bar ────────────────────────────────────────────────────
function MetricBar({ icon: Icon, label, value }) {
  if (value == null) return null
  const color =
    value >= 95 ? 'var(--red)'    :
    value >= 80 ? 'var(--yellow)' :
    'var(--accent-blue)'
  return (
    <div style={{ marginBottom: '0.55rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <Icon size={12} /> {label}
        </span>
        <span style={{ fontSize: '0.78rem', fontWeight: 600, color }}>{value.toFixed(1)}%</span>
      </div>
      <div style={{ height: '4px', borderRadius: '2px', background: 'var(--border)', overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.min(value, 100)}%`, background: color, borderRadius: '2px', transition: 'width 0.4s' }} />
      </div>
    </div>
  )
}

// ── Failed check chip ─────────────────────────────────────────────
const CHECK_LABELS = {
  FIREWALL_DISABLED:     'Firewall off',
  DEFENDER_DISABLED:     'Defender off',
  BITLOCKER_DISABLED:    'No BitLocker',
  LOCAL_ADMIN_DETECTED:  'Local admin',
  RDP_ENABLED:           'RDP open',
  USB_STORAGE_ENABLED:   'USB allowed',
  UNKNOWN_APPS_DETECTED: 'Unknown apps',
}

function FailChip({ checkId }) {
  return (
    <span style={{
      fontSize: '0.68rem', padding: '0.15rem 0.45rem',
      borderRadius: '999px',
      background: 'rgba(239,68,68,0.12)',
      color: '#ef4444',
      fontWeight: 600,
    }}>
      {CHECK_LABELS[checkId] || checkId}
    </span>
  )
}

// ── Main card ─────────────────────────────────────────────────────
export default function MachineCard({ machine, onClick }) {
  const trustLevel = machine.trust_level || 'unknown'
  const meta       = TRUST_META[trustLevel] || TRUST_META.unknown
  const { Icon: TrustIcon } = meta
  const failedChecks = machine.failed_checks || []

  return (
    <div
      style={{
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: '1.25rem',
        cursor: 'pointer',
        transition: 'transform 0.15s, box-shadow 0.15s',
        position: 'relative',
        overflow: 'hidden',
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform   = 'translateY(-2px)'
        e.currentTarget.style.boxShadow   = meta.glow
        e.currentTarget.style.borderColor = meta.color
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform   = 'none'
        e.currentTarget.style.boxShadow   = 'none'
        e.currentTarget.style.borderColor = 'var(--border)'
      }}
    >
      {/* Trust-coloured accent bar */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '3px', background: meta.color }} />

      {/* Header: hostname + online badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
        <div>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.2rem' }}>{machine.hostname}</h3>
          <p style={{ fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            {machine.ip_address || 'No IP'}
          </p>
        </div>
        <span style={{
          display: 'flex', alignItems: 'center', gap: '0.3rem',
          fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase',
          letterSpacing: '0.05em', padding: '0.18rem 0.5rem',
          borderRadius: '999px',
          background: machine.is_online ? 'rgba(34,197,94,0.12)' : 'rgba(100,116,139,0.12)',
          color: machine.is_online ? '#22c55e' : 'var(--text-muted)',
        }}>
          {machine.is_online ? <Wifi size={10} /> : <WifiOff size={10} />}
          {machine.is_online ? 'Online' : 'Offline'}
        </span>
      </div>

      {/* Trust badge + risk score */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.75rem' }}>
        <span style={{
          display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
          fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase',
          letterSpacing: '0.05em', padding: '0.2rem 0.55rem',
          borderRadius: '999px',
          background: `${meta.color}18`,
          color: meta.color,
        }}>
          <TrustIcon size={11} />
          {meta.label}
        </span>
        {machine.risk_score != null && (
          <span style={{ marginLeft: 'auto', fontSize: '0.72rem', fontWeight: 700, color: meta.color }}>
            Risk: {machine.risk_score}/100
          </span>
        )}
      </div>

      {/* Failed check chips */}
      {failedChecks.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem', marginBottom: '0.75rem' }}>
          {failedChecks.slice(0, 3).map((c) => <FailChip key={c} checkId={c} />)}
          {failedChecks.length > 3 && (
            <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>+{failedChecks.length - 3} more</span>
          )}
        </div>
      )}

      {/* Metric bars */}
      {machine.is_online && (
        <div style={{ paddingTop: '0.5rem', borderTop: '1px solid var(--border)' }}>
          <MetricBar icon={Cpu}         label="CPU"  value={machine.cpu_usage}  />
          <MetricBar icon={MemoryStick} label="RAM"  value={machine.ram_usage}  />
          <MetricBar icon={HardDrive}   label="Disk" value={machine.disk_usage} />
        </div>
      )}

      {/* Current user footer */}
      {machine.current_user && (
        <div style={{ marginTop: '0.6rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
          <User size={11} style={{ color: 'var(--text-muted)' }} />
          <span style={{ fontSize: '0.73rem', color: 'var(--text-muted)' }}>{machine.current_user}</span>
        </div>
      )}
    </div>
  )
}
