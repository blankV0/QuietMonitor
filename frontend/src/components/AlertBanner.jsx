/**
 * QuietMonitor – components/AlertBanner.jsx
 * ───────────────────────────────────────────
 * Displays a horizontal scrollable strip of active (unresolved) alerts.
 * Each alert shows its severity colour, type, and message.
 * Props:
 *   alerts      – array of alert objects from the API
 *   onResolve   – (alertId) => void  called when the user dismisses an alert
 */

import React from 'react'
import { AlertTriangle, AlertCircle, X } from 'lucide-react'

// Map severity → colour token
const SEVERITY_COLOR = {
  critical: 'var(--red)',
  warning:  'var(--yellow)',
}

const styles = {
  strip: {
    display: 'flex',
    gap: '0.75rem',
    padding: '0.6rem 1.5rem',
    background: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border)',
    overflowX: 'auto',
    minHeight: '50px',
    alignItems: 'center',
  },
  empty: {
    fontSize: '0.82rem',
    color: 'var(--text-muted)',
  },
  chip: (severity) => ({
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    padding: '0.3rem 0.75rem',
    borderRadius: '999px',
    border: `1px solid ${SEVERITY_COLOR[severity] || 'var(--border)'}`,
    background: `${SEVERITY_COLOR[severity] || 'var(--border)'}18`,
    color: SEVERITY_COLOR[severity] || 'var(--text-secondary)',
    fontSize: '0.8rem',
    whiteSpace: 'nowrap',
    flexShrink: 0,
  }),
  closeBtn: {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    color: 'inherit',
    padding: '0',
    display: 'flex',
    alignItems: 'center',
    opacity: 0.7,
  },
}

export default function AlertBanner({ alerts = [], onResolve }) {
  if (alerts.length === 0) {
    return (
      <div style={styles.strip}>
        <span style={styles.empty}>✅ No active alerts</span>
      </div>
    )
  }

  return (
    <div style={styles.strip}>
      {alerts.map((alert) => {
        const Icon = alert.severity === 'critical' ? AlertCircle : AlertTriangle
        return (
          <div key={alert.id} style={styles.chip(alert.severity)}>
            <Icon size={13} />
            <span>
              <strong>{alert.alert_type.replace('_', ' ')}</strong>
              {' – '}
              {alert.message}
            </span>
            {onResolve && (
              <button style={styles.closeBtn} onClick={() => onResolve(alert.id)} title="Dismiss">
                <X size={12} />
              </button>
            )}
          </div>
        )
      })}
    </div>
  )
}
