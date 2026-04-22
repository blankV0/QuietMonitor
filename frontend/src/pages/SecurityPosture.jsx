/**
 * QuietMonitor - pages/SecurityPosture.jsx
 * -----------------------------------------
 * Full SOC-style security posture page for a single machine.
 *
 * Sections:
 *   1. Header  - hostname, trust/compliance/online badges, back buttons
 *   2. Score row - risk gauge + compliance status side by side
 *   3. Risk check breakdown table (all 7 checks with pass/fail)
 *   4. Compliance policy rules list (4 rules with detail messages)
 *   5. Installed apps + local admins panels
 */

import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, Server, Wifi, WifiOff,
  ShieldCheck, ShieldAlert, ShieldOff,
  CheckCircle2, XCircle, HelpCircle,
  Flame, Lock, Unlock, Monitor, Usb, Users, Package,
  LayoutDashboard,
} from 'lucide-react'

import Navbar from '../components/Navbar.jsx'
import { getMachine, getMachineRisk, getMachineCompliance } from '../api/api.js'

// ── Trust meta ────────────────────────────────────────────────────
const TRUST_META = {
  trusted:  { color: '#22c55e', label: 'Trusted',  Icon: ShieldCheck },
  warning:  { color: '#eab308', label: 'Warning',  Icon: ShieldAlert },
  critical: { color: '#ef4444', label: 'Critical', Icon: ShieldOff   },
}

// ── Risk check icon map ───────────────────────────────────────────
const CHECK_ICONS = {
  FIREWALL_DISABLED:     Flame,
  DEFENDER_DISABLED:     ShieldCheck,
  BITLOCKER_DISABLED:    Lock,
  LOCAL_ADMIN_DETECTED:  Users,
  RDP_ENABLED:           Monitor,
  USB_STORAGE_ENABLED:   Usb,
  UNKNOWN_APPS_DETECTED: Package,
}

// ── Risk gauge (SVG semicircle) ───────────────────────────────────
function RiskGauge({ score, size = 160 }) {
  if (score == null) return null
  const color =
    score <= 30 ? '#22c55e' :
    score <= 60 ? '#eab308' :
    '#ef4444'
  const label =
    score <= 30 ? 'TRUSTED' :
    score <= 60 ? 'WARNING' :
    'CRITICAL'

  const r  = 56
  const cx = 90
  const cy = 90
  const startAngle = Math.PI
  const endAngle   = 0
  const scoreAngle = startAngle - (score / 100) * Math.PI

  const toXY = (a, rad) => [cx + rad * Math.cos(a), cy + rad * Math.sin(a)]
  const [sx, sy] = toXY(startAngle, r)
  const [ex, ey] = toXY(scoreAngle, r)
  const largeArc = (startAngle - scoreAngle) > Math.PI ? 1 : 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={size} height={size * 0.6} viewBox="0 0 180 105">
        {/* Track */}
        <path
          d={`M ${toXY(startAngle, r)[0]} ${toXY(startAngle, r)[1]} A ${r} ${r} 0 0 0 ${toXY(endAngle, r)[0]} ${toXY(endAngle, r)[1]}`}
          fill="none" stroke="var(--border)" strokeWidth="12" strokeLinecap="round"
        />
        {/* Fill */}
        {score > 0 && (
          <path
            d={`M ${sx} ${sy} A ${r} ${r} 0 ${largeArc} 0 ${ex} ${ey}`}
            fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          />
        )}
        {/* Score */}
        <text x={cx} y={cy - 6} textAnchor="middle" fill={color} fontSize="28" fontWeight="800">
          {score}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--text-muted)" fontSize="10">
          / 100
        </text>
      </svg>
      <span style={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em', color, marginTop: '0.25rem' }}>
        {label}
      </span>
    </div>
  )
}

// ── Badge ─────────────────────────────────────────────────────────
function Badge({ color, icon: Icon, label }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
      padding: '0.3rem 0.75rem', borderRadius: '999px',
      fontSize: '0.78rem', fontWeight: 700,
      background: `${color}18`, color,
    }}>
      {Icon && <Icon size={13} />}
      {label}
    </span>
  )
}

// ── Check row ─────────────────────────────────────────────────────
function RiskCheckRow({ check }) {
  const CheckIcon = CHECK_ICONS[check.check_id] || ShieldCheck
  const StatusIcon = check.passed ? CheckCircle2 : XCircle
  const color = check.passed ? '#22c55e' : '#ef4444'

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '28px 1fr auto auto',
      alignItems: 'center',
      gap: '0.75rem',
      padding: '0.65rem 0',
      borderBottom: '1px solid var(--border)',
    }}>
      <CheckIcon size={16} style={{ color }} />
      <div>
        <div style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
          {check.label}
        </div>
        <div style={{ fontSize: '0.73rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {check.check_id}
        </div>
      </div>
      <span style={{
        fontSize: '0.72rem', fontWeight: 700,
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
        background: 'var(--bg-secondary)',
        padding: '0.15rem 0.4rem',
        borderRadius: '4px',
        whiteSpace: 'nowrap',
      }}>
        {check.weight > 0 ? `−${check.weight} pts` : 'info'}
      </span>
      <StatusIcon size={18} style={{ color }} />
    </div>
  )
}

// ── Compliance rule row ───────────────────────────────────────────
function ComplianceRuleRow({ rule }) {
  const color = rule.passed ? '#22c55e' : (rule.severity === 'critical' ? '#ef4444' : '#eab308')
  const StatusIcon = rule.passed ? CheckCircle2 : XCircle
  const severityBg = rule.severity === 'critical' ? 'rgba(239,68,68,0.1)' : 'rgba(234,179,8,0.1)'
  const severityColor = rule.severity === 'critical' ? '#ef4444' : '#eab308'

  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: '0.85rem',
      padding: '0.75rem 0', borderBottom: '1px solid var(--border)',
    }}>
      <StatusIcon size={18} style={{ color, flexShrink: 0, marginTop: '1px' }} />
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
          <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {rule.label}
          </span>
          {!rule.passed && (
            <span style={{
              fontSize: '0.65rem', fontWeight: 700, textTransform: 'uppercase',
              padding: '0.1rem 0.4rem', borderRadius: '4px',
              background: severityBg, color: severityColor,
            }}>
              {rule.severity}
            </span>
          )}
        </div>
        <div style={{ fontSize: '0.77rem', color: 'var(--text-muted)' }}>
          {rule.details}
        </div>
      </div>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────
export default function SecurityPosture() {
  const { id }   = useParams()
  const navigate = useNavigate()

  const [machine,    setMachine]    = useState(null)
  const [riskDetail, setRiskDetail] = useState(null)
  const [compliance, setCompliance] = useState(null)
  const [loading,    setLoading]    = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [machineRes, riskRes, compRes] = await Promise.all([
          getMachine(id),
          getMachineRisk(id).catch(() => ({ data: null })),
          getMachineCompliance(id).catch(() => ({ data: null })),
        ])
        setMachine(machineRes.data)
        setRiskDetail(riskRes.data)
        setCompliance(compRes.data)
      } catch (err) {
        console.error('SecurityPosture fetch error:', err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  const s = {
    page:  { minHeight: '100vh', background: 'var(--bg-primary)' },
    main:  { padding: '1.5rem', maxWidth: '1200px', margin: '0 auto' },
    backRow: {
      display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem',
    },
    backBtn: {
      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
      color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer',
      background: 'none', border: 'none', padding: 0,
    },
    header: {
      display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap',
    },
    card: {
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '1.25rem',
    },
    cardTitle: {
      fontSize: '0.78rem', fontWeight: 600, textTransform: 'uppercase',
      letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: '1rem',
    },
    twoCol: {
      display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginBottom: '1.25rem',
    },
  }

  if (loading) {
    return (
      <div style={s.page}>
        <Navbar />
        <main style={s.main}>
          <p style={{ color: 'var(--text-muted)' }}>Loading security posture...</p>
        </main>
      </div>
    )
  }

  if (!machine) {
    return (
      <div style={s.page}>
        <Navbar />
        <main style={s.main}>
          <p style={{ color: 'var(--red)' }}>Machine not found.</p>
        </main>
      </div>
    )
  }

  const trustMeta     = TRUST_META[machine.trust_level] || null
  const isCompliant   = compliance?.compliant
  const compSeverity  = compliance?.severity || 'unknown'

  const compColor =
    compSeverity === 'compliant' ? '#22c55e' :
    compSeverity === 'warning'   ? '#eab308' :
    compSeverity === 'critical'  ? '#ef4444' :
    'var(--text-muted)'

  return (
    <div style={s.page}>
      <Navbar />
      <main style={s.main}>

        {/* Back buttons */}
        <div style={s.backRow}>
          <button style={s.backBtn} onClick={() => navigate('/')}>
            <LayoutDashboard size={14} /> Dashboard
          </button>
          <span style={{ color: 'var(--border)' }}>/</span>
          <button style={s.backBtn} onClick={() => navigate(`/machines/${id}`)}>
            <ArrowLeft size={14} /> {machine.hostname}
          </button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem', marginLeft: '0.25rem' }}>
            / Security Posture
          </span>
        </div>

        {/* Header */}
        <div style={s.header}>
          <Server size={30} style={{ color: 'var(--cyan)' }} />
          <div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
              {machine.hostname}
            </h1>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {machine.ip_address || 'No IP registered'} &nbsp;|&nbsp; Security Posture
            </p>
          </div>

          <Badge
            color={machine.is_online ? '#22c55e' : 'var(--text-muted)'}
            icon={machine.is_online ? Wifi : WifiOff}
            label={machine.is_online ? 'Online' : 'Offline'}
          />
          {trustMeta && (
            <Badge color={trustMeta.color} icon={trustMeta.Icon} label={trustMeta.label} />
          )}
          {compliance && (
            <Badge
              color={compColor}
              icon={isCompliant ? CheckCircle2 : XCircle}
              label={isCompliant ? 'COMPLIANT' : 'NON-COMPLIANT'}
            />
          )}
        </div>

        {/* Score row: risk gauge + compliance summary */}
        <div style={{ ...s.twoCol, gridTemplateColumns: '1fr 1fr' }}>

          {/* Risk score card */}
          <div style={{ ...s.card, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
            <p style={s.cardTitle}>Risk Score</p>
            <RiskGauge score={machine.risk_score} size={180} />
            {riskDetail && (
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  {riskDetail.failed_checks.length} of {riskDetail.checks.length} checks failed
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  max possible: {riskDetail.max_possible_score} pts
                </div>
              </div>
            )}
          </div>

          {/* Compliance summary card */}
          <div style={s.card}>
            <p style={s.cardTitle}>Compliance Policy</p>
            {compliance ? (
              <>
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  gap: '0.5rem', marginBottom: '1rem',
                  padding: '0.75rem',
                  background: `${compColor}10`,
                  borderRadius: 'var(--radius-sm)',
                  border: `1px solid ${compColor}30`,
                }}>
                  {isCompliant
                    ? <CheckCircle2 size={22} color="#22c55e" />
                    : <XCircle size={22} color="#ef4444" />
                  }
                  <span style={{ fontSize: '1rem', fontWeight: 700, color: compColor }}>
                    {isCompliant ? 'All policies passed' : `${compliance.failed_rules.length} polic${compliance.failed_rules.length === 1 ? 'y' : 'ies'} failed`}
                  </span>
                </div>
                {compliance.failed_rules.length > 0 && (
                  <div>
                    {compliance.failed_rules.map(rid => (
                      <div key={rid} style={{
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                        padding: '0.3rem 0', fontSize: '0.82rem', color: '#ef4444',
                        fontFamily: 'var(--font-mono)',
                      }}>
                        <XCircle size={13} /> {rid}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No compliance data available.</p>
            )}
          </div>
        </div>

        {/* Risk checks table */}
        {riskDetail?.checks?.length > 0 && (
          <div style={{ ...s.card, marginBottom: '1.25rem' }}>
            <p style={s.cardTitle}>Risk Check Breakdown</p>
            {riskDetail.checks.map(check => (
              <RiskCheckRow key={check.check_id} check={check} />
            ))}
          </div>
        )}

        {/* Compliance rules list */}
        {compliance?.rules?.length > 0 && (
          <div style={{ ...s.card, marginBottom: '1.25rem' }}>
            <p style={s.cardTitle}>Compliance Policy Rules</p>
            {compliance.rules.map(rule => (
              <ComplianceRuleRow key={rule.rule_id} rule={rule} />
            ))}
          </div>
        )}

        {/* Apps + Admins row */}
        <div style={s.twoCol}>

          {/* Local admins */}
          <div style={s.card}>
            <p style={s.cardTitle}>Local Administrator Accounts</p>
            {machine.local_admins?.length > 0 ? (
              machine.local_admins.map((name, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.4rem 0', borderBottom: '1px solid var(--border)',
                  fontSize: '0.85rem',
                }}>
                  <Users size={14} style={{ color: 'var(--text-muted)' }} />
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{name}</span>
                </div>
              ))
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                {machine.local_admins === null ? 'No data collected yet.' : 'No local admins detected.'}
              </p>
            )}
          </div>

          {/* Installed apps */}
          <div style={s.card}>
            <p style={s.cardTitle}>
              Installed Applications
              {machine.installed_apps && (
                <span style={{ marginLeft: '0.5rem', color: 'var(--text-muted)', fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>
                  ({machine.installed_apps.length})
                </span>
              )}
            </p>
            {machine.installed_apps?.length > 0 ? (
              <div style={{ maxHeight: '260px', overflowY: 'auto' }}>
                {machine.installed_apps.map((app, i) => (
                  <div key={i} style={{
                    padding: '0.3rem 0',
                    borderBottom: '1px solid var(--border)',
                    fontSize: '0.8rem',
                    color: 'var(--text-secondary)',
                    fontFamily: 'var(--font-mono)',
                  }}>
                    {app}
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                {machine.installed_apps === null ? 'No data collected yet.' : 'No applications found.'}
              </p>
            )}
          </div>
        </div>

      </main>
    </div>
  )
}
