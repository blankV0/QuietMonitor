/**
 * QuietMonitor – pages/MachineDetail.jsx
 * ────────────────────────────────────────
 * Detail view for a single machine.
 *
 * Sections:
 *   1. Header (hostname, online/trust badges, back button)
 *   2. Live metrics tiles (CPU / RAM / Disk)
 *   3. Zero Trust CompliancePanel
 *   4. System info card
 *   5. Historical charts
 */

import React, { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import {
  ArrowLeft, Cpu, HardDrive, MemoryStick,
  Wifi, WifiOff, User, Shield, Clock, Server,
  ShieldCheck, ShieldAlert, ShieldOff,
} from 'lucide-react'

import Navbar          from '../components/Navbar.jsx'
import CompliancePanel from '../components/CompliancePanel.jsx'
import { getMachine, getMachineHistory } from '../api/api.js'

// ── Helpers ───────────────────────────────────────────────────────
function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'
}

function fmtTime(iso) {
  return iso ? new Date(iso).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : ''
}

function getStatusColor(value, warnAt = 80, critAt = 95) {
  if (value == null) return 'var(--text-muted)'
  if (value >= critAt) return 'var(--red)'
  if (value >= warnAt) return 'var(--yellow)'
  return 'var(--green)'
}

const TRUST_META = {
  trusted:  { color: '#22c55e', label: 'Trusted',  Icon: ShieldCheck },
  warning:  { color: '#eab308', label: 'Warning',  Icon: ShieldAlert },
  critical: { color: '#ef4444', label: 'Critical', Icon: ShieldOff   },
}

// ── Big metric tile ────────────────────────────────────────────────
function MetricTile({ icon: Icon, label, value, warnAt, critAt }) {
  const color = value != null ? getStatusColor(value, warnAt, critAt) : 'var(--text-muted)'
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '1.25rem',
      display: 'flex', flexDirection: 'column', gap: '0.5rem',
      borderBottom: `3px solid ${color}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
        <Icon size={16} /> {label}
      </div>
      <span style={{ fontSize: '2.2rem', fontWeight: 700, color, lineHeight: 1 }}>
        {value != null ? `${value.toFixed(1)}%` : '—'}
      </span>
      <div style={{ height: '4px', borderRadius: '2px', background: 'var(--border)' }}>
        <div style={{ height: '100%', width: `${Math.min(value ?? 0, 100)}%`, background: color, borderRadius: '2px' }} />
      </div>
    </div>
  )
}

// ── Info row ──────────────────────────────────────────────────────
function InfoRow({ icon: Icon, label, value }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.75rem 0', borderBottom: '1px solid var(--border)' }}>
      <Icon size={15} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
      <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', minWidth: '120px' }}>{label}</span>
      <span style={{ fontSize: '0.88rem', color: 'var(--text-primary)', fontWeight: 500 }}>{value || '—'}</span>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────
export default function MachineDetail() {
  const { id }   = useParams()
  const navigate = useNavigate()

  const [machine, setMachine] = useState(null)
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [machineRes, historyRes] = await Promise.all([
          getMachine(id),
          getMachineHistory(id, 60),
        ])
        setMachine(machineRes.data)
        setHistory([...historyRes.data].reverse())
      } catch (err) {
        console.error('MachineDetail fetch error:', err)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [id])

  const s = {
    page:    { minHeight: '100vh', background: 'var(--bg-primary)' },
    main:    { padding: '1.5rem', maxWidth: '1200px', margin: '0 auto' },
    backBtn: {
      display: 'inline-flex', alignItems: 'center', gap: '0.4rem',
      color: 'var(--text-secondary)', fontSize: '0.85rem', cursor: 'pointer',
      background: 'none', border: 'none', marginBottom: '1rem', padding: 0,
    },
    header: { display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' },
    hostname: { fontSize: '1.5rem', fontWeight: 700 },
    badge: (color) => ({
      padding: '0.25rem 0.75rem', borderRadius: '999px',
      fontSize: '0.78rem', fontWeight: 600,
      background: `${color}18`, color,
      display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
    }),
    grid3:  { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.5rem' },
    twoCol: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' },
    card:   { background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: '1.25rem' },
    cardTitle: { fontSize: '0.82rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: '0.75rem' },
  }

  if (loading) {
    return <div style={s.page}><Navbar /><main style={s.main}><p style={{ color: 'var(--text-muted)' }}>Loading machine data…</p></main></div>
  }

  if (!machine) {
    return <div style={s.page}><Navbar /><main style={s.main}><p style={{ color: 'var(--red)' }}>Machine not found.</p></main></div>
  }

  const trustMeta = TRUST_META[machine.trust_level] || null

  return (
    <div style={s.page}>
      <Navbar />
      <main style={s.main}>

        {/* Back */}
        <button style={s.backBtn} onClick={() => navigate('/')}>
          <ArrowLeft size={15} /> Back to Dashboard
        </button>

        {/* Header */}
        <div style={s.header}>
          <Server size={28} style={{ color: 'var(--accent-blue)' }} />
          <div>
            <h1 style={s.hostname}>{machine.hostname}</h1>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              {machine.ip_address || 'No IP registered'}
            </p>
          </div>

          {/* Online/Offline badge */}
          <span style={s.badge(machine.is_online ? '#22c55e' : 'var(--text-muted)')}>
            {machine.is_online ? <Wifi size={12} /> : <WifiOff size={12} />}
            {machine.is_online ? 'Online' : 'Offline'}
          </span>

          {/* Trust level badge */}
          {trustMeta && (
            <span style={s.badge(trustMeta.color)}>
              <trustMeta.Icon size={12} />
              {trustMeta.label}
            </span>
          )}
        </div>

        {/* Live metric tiles */}
        <div style={s.grid3}>
          <MetricTile icon={Cpu}         label="CPU Usage"  value={machine.cpu_usage}  warnAt={80} critAt={95} />
          <MetricTile icon={MemoryStick} label="RAM Usage"  value={machine.ram_usage}  warnAt={85} critAt={95} />
          <MetricTile icon={HardDrive}   label="Disk Usage" value={machine.disk_usage} warnAt={85} critAt={95} />
        </div>

        {/* ── Zero Trust Compliance Panel ── */}
        <div style={{ marginBottom: '1.5rem' }}>
          <CompliancePanel machine={machine} />
        </div>

        {/* System info + CPU sparkline */}
        <div style={s.twoCol}>
          <div style={s.card}>
            <p style={s.cardTitle}>System Information</p>
            <InfoRow icon={User}   label="Current User"  value={machine.current_user} />
            <InfoRow icon={Shield} label="Antivirus"     value={machine.antivirus_status} />
            <InfoRow icon={Clock}  label="Last Reboot"   value={fmtDate(machine.last_reboot)} />
            <InfoRow icon={Clock}  label="Last Seen"     value={fmtDate(machine.last_seen)} />
            <InfoRow icon={Server} label="Registered"    value={fmtDate(machine.registered_at)} />
          </div>

          <div style={s.card}>
            <p style={s.cardTitle}>CPU History (last {history.length} snapshots)</p>
            <div style={{ height: '220px' }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                  <XAxis dataKey="recorded_at" tickFormatter={fmtTime} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                  <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }}
                    labelFormatter={fmtDate}
                  />
                  <Line type="monotone" dataKey="cpu_usage" name="CPU %" stroke="var(--accent-blue)" dot={false} strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* Combined history chart */}
        <div style={s.card}>
          <p style={s.cardTitle}>Resource History – CPU / RAM / Disk</p>
          <div style={{ height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="recorded_at" tickFormatter={fmtTime} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                <YAxis domain={[0, 100]} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: '8px' }}
                  labelFormatter={fmtDate}
                />
                <Legend wrapperStyle={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }} />
                <Line type="monotone" dataKey="cpu_usage"  name="CPU %"  stroke="var(--accent-blue)" dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="ram_usage"  name="RAM %"  stroke="var(--green)"       dot={false} strokeWidth={2} />
                <Line type="monotone" dataKey="disk_usage" name="Disk %" stroke="var(--yellow)"      dot={false} strokeWidth={2} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

      </main>
    </div>
  )
}
