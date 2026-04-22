/**
 * QuietMonitor - pages/Dashboard.jsx
 * ------------------------------------
 * SOC-style Zero Trust compliance dashboard.
 *
 * Features:
 *   - Threat-level banner: fleet risk + compliance rate
 *   - Summary stats: Total / Online / Offline / Alerts / Trusted / Warning / Critical
 *   - Compliance summary row: Compliant / Non-Compliant / Rate / Top Failure
 *   - Active alerts strip (AlertBanner)
 *   - Search + filter toolbar
 *   - Grid of MachineCard components
 *   - Auto-refresh every 30 seconds
 */

import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Server, Wifi, WifiOff, Bell, RefreshCw,
  ShieldCheck, ShieldAlert, ShieldOff,
  Activity, CheckCircle2, XCircle, TrendingUp,
} from 'lucide-react'

import Navbar       from '../components/Navbar.jsx'
import AlertBanner  from '../components/AlertBanner.jsx'
import MachineCard  from '../components/MachineCard.jsx'
import SearchBar    from '../components/SearchBar.jsx'
import {
  getMachines, getAlerts, resolveAlert,
  getFleetRiskSummary, getFleetComplianceStatus,
} from '../api/api.js'

const REFRESH_INTERVAL = 30_000

export default function Dashboard() {
  const navigate = useNavigate()

  const [machines,    setMachines]    = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [riskSummary, setRiskSummary] = useState(null)
  const [compliance,  setCompliance]  = useState(null)
  const [search,      setSearch]      = useState('')
  const [filter,      setFilter]      = useState('all')
  const [loading,     setLoading]     = useState(true)
  const [lastUpdate,  setLastUpdate]  = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [machinesRes, alertsRes, riskRes, compRes] = await Promise.all([
        getMachines(),
        getAlerts(),
        getFleetRiskSummary().catch(() => ({ data: null })),
        getFleetComplianceStatus().catch(() => ({ data: null })),
      ])
      setMachines(machinesRes.data)
      setAlerts(alertsRes.data)
      setRiskSummary(riskRes.data)
      setCompliance(compRes.data)
      setLastUpdate(new Date())
    } catch (err) {
      console.error('Dashboard fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, REFRESH_INTERVAL)
    return () => clearInterval(interval)
  }, [fetchData])

  const handleResolve = async (alertId) => {
    await resolveAlert(alertId)
    setAlerts((prev) => prev.filter((a) => a.id !== alertId))
  }

  // -- Derived counts
  const online   = machines.filter((m) => m.is_online).length
  const offline  = machines.length - online
  const trusted  = machines.filter((m) => m.trust_level === 'trusted').length
  const warning  = machines.filter((m) => m.trust_level === 'warning').length
  const critical = machines.filter((m) => m.trust_level === 'critical').length

  const fleetThreat =
    critical > 0 ? 'critical' :
    warning  > 0 ? 'warning'  :
    machines.length > 0 ? 'trusted' : null

  const THREAT_COLOR = { critical: '#ef4444', warning: '#eab308', trusted: '#22c55e' }
  const THREAT_LABEL = { critical: 'CRITICAL', warning: 'ELEVATED', trusted: 'NORMAL' }

  // -- Filtered list
  const filtered = machines
    .filter((m) => {
      if (filter === 'online')   return m.is_online
      if (filter === 'trusted')  return m.trust_level === 'trusted'
      if (filter === 'warning')  return m.trust_level === 'warning'
      if (filter === 'critical') return m.trust_level === 'critical'
      return true
    })
    .filter((m) => !search || m.hostname.toLowerCase().includes(search.toLowerCase()))

  // -- Styles
  const s = {
    page:  { minHeight: '100vh', background: 'var(--bg-primary)' },
    main:  { padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' },

    threatBanner: (color) => ({
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      flexWrap: 'wrap', gap: '0.75rem',
      padding: '0.75rem 1.25rem', marginBottom: '1.25rem',
      background: `${color}10`,
      border: `1px solid ${color}30`,
      borderLeft: `4px solid ${color}`,
      borderRadius: 'var(--radius)',
    }),
    threatLabel: (color) => ({
      display: 'flex', alignItems: 'center', gap: '0.5rem',
      fontSize: '0.78rem', fontWeight: 700, letterSpacing: '0.1em', color,
    }),
    threatMeta: {
      display: 'flex', alignItems: 'center', gap: '1.5rem',
      fontSize: '0.78rem', color: 'var(--text-muted)',
      fontFamily: 'var(--font-mono)',
    },
    threatStat: (color) => ({ display: 'flex', alignItems: 'center', gap: '0.3rem', color }),

    statsRow: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
      gap: '0.85rem', marginBottom: '1rem',
    },
    statCard: (color) => ({
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '0.9rem 1.1rem',
      display: 'flex', flexDirection: 'column', gap: '0.3rem',
      borderLeft: `3px solid ${color}`,
    }),
    statValue: { fontSize: '1.7rem', fontWeight: 700, lineHeight: 1 },
    statLabel: { fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' },

    complianceRow: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
      gap: '0.85rem', marginBottom: '1.25rem',
    },
    compCard: (color) => ({
      background: 'var(--bg-card)',
      border: `1px solid ${color}30`,
      borderRadius: 'var(--radius)', padding: '0.85rem 1.1rem',
      display: 'flex', alignItems: 'center', gap: '0.75rem',
    }),
    compIcon: (color) => ({
      width: '36px', height: '36px', borderRadius: '8px',
      background: `${color}15`, display: 'flex', alignItems: 'center', justifyContent: 'center',
      flexShrink: 0,
    }),
    compValue: { fontSize: '1.5rem', fontWeight: 700, lineHeight: 1 },
    compLabel: { fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginTop: '0.2rem' },

    toolbar: {
      display: 'flex', alignItems: 'center', flexWrap: 'wrap',
      gap: '0.6rem', marginBottom: '1.25rem',
    },
    filterBtn: (active, color = 'var(--accent-blue)') => ({
      padding: '0.45rem 0.9rem', borderRadius: 'var(--radius-sm)',
      border: `1px solid ${active ? color : 'var(--border)'}`,
      background: active ? `${color}20` : 'transparent',
      color: active ? color : 'var(--text-secondary)',
      fontSize: '0.82rem', cursor: 'pointer', transition: 'all 0.15s',
    }),
    refreshBtn: {
      display: 'flex', alignItems: 'center', gap: '0.4rem',
      padding: '0.45rem 0.85rem', borderRadius: 'var(--radius-sm)',
      border: '1px solid var(--border)', background: 'transparent',
      color: 'var(--text-secondary)', fontSize: '0.8rem', cursor: 'pointer',
      marginLeft: 'auto',
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
      gap: '1rem',
    },
  }

  return (
    <div style={s.page}>
      <Navbar />
      <AlertBanner alerts={alerts} onResolve={handleResolve} />

      <main style={s.main}>

        {/* -- SOC Threat Banner -- */}
        {fleetThreat && (
          <div style={s.threatBanner(THREAT_COLOR[fleetThreat])}>
            <div style={s.threatLabel(THREAT_COLOR[fleetThreat])}>
              <Activity size={14} />
              THREAT LEVEL -- {THREAT_LABEL[fleetThreat]}
            </div>
            <div style={s.threatMeta}>
              {riskSummary && (
                <>
                  <span style={s.threatStat('#ef4444')}>
                    <ShieldOff size={12} /> {riskSummary.critical} critical
                  </span>
                  <span style={s.threatStat('#eab308')}>
                    <ShieldAlert size={12} /> {riskSummary.warning} warning
                  </span>
                  <span style={s.threatStat('#22c55e')}>
                    <ShieldCheck size={12} /> {riskSummary.trusted} trusted
                  </span>
                  {riskSummary.avg_risk_score != null && (
                    <span>avg risk {riskSummary.avg_risk_score.toFixed(0)}</span>
                  )}
                </>
              )}
              {lastUpdate && (
                <span>updated {lastUpdate.toLocaleTimeString()}</span>
              )}
            </div>
          </div>
        )}

        {/* -- Summary stats -- */}
        <div style={s.statsRow}>
          <div style={s.statCard('var(--accent-blue)')}>
            <Server size={16} style={{ color: 'var(--accent-blue)' }} />
            <span style={s.statValue}>{machines.length}</span>
            <span style={s.statLabel}>Total</span>
          </div>
          <div style={s.statCard('var(--green)')}>
            <Wifi size={16} style={{ color: 'var(--green)' }} />
            <span style={s.statValue}>{online}</span>
            <span style={s.statLabel}>Online</span>
          </div>
          <div style={s.statCard('var(--text-muted)')}>
            <WifiOff size={16} style={{ color: 'var(--text-muted)' }} />
            <span style={s.statValue}>{offline}</span>
            <span style={s.statLabel}>Offline</span>
          </div>
          <div style={s.statCard('var(--red)')}>
            <Bell size={16} style={{ color: 'var(--red)' }} />
            <span style={s.statValue}>{alerts.length}</span>
            <span style={s.statLabel}>Alerts</span>
          </div>
          <div style={s.statCard('#22c55e')}>
            <ShieldCheck size={16} style={{ color: '#22c55e' }} />
            <span style={{ ...s.statValue, color: '#22c55e' }}>{trusted}</span>
            <span style={s.statLabel}>Trusted</span>
          </div>
          <div style={s.statCard('#eab308')}>
            <ShieldAlert size={16} style={{ color: '#eab308' }} />
            <span style={{ ...s.statValue, color: '#eab308' }}>{warning}</span>
            <span style={s.statLabel}>Warning</span>
          </div>
          <div style={s.statCard('#ef4444')}>
            <ShieldOff size={16} style={{ color: '#ef4444' }} />
            <span style={{ ...s.statValue, color: '#ef4444' }}>{critical}</span>
            <span style={s.statLabel}>Critical</span>
          </div>
        </div>

        {/* -- Compliance summary row -- */}
        {compliance && (
          <div style={s.complianceRow}>
            <div style={s.compCard('#22c55e')}>
              <div style={s.compIcon('#22c55e')}>
                <CheckCircle2 size={18} color="#22c55e" />
              </div>
              <div>
                <div style={{ ...s.compValue, color: '#22c55e' }}>{compliance.compliant}</div>
                <div style={s.compLabel}>Policy Compliant</div>
              </div>
            </div>
            <div style={s.compCard('#ef4444')}>
              <div style={s.compIcon('#ef4444')}>
                <XCircle size={18} color="#ef4444" />
              </div>
              <div>
                <div style={{ ...s.compValue, color: '#ef4444' }}>{compliance.non_compliant}</div>
                <div style={s.compLabel}>Non-Compliant</div>
              </div>
            </div>
            <div style={s.compCard('var(--cyan)')}>
              <div style={s.compIcon('var(--cyan)')}>
                <TrendingUp size={18} color="var(--cyan)" />
              </div>
              <div>
                <div style={{ ...s.compValue, color: 'var(--cyan)', fontFamily: 'var(--font-mono)' }}>
                  {compliance.compliance_rate.toFixed(1)}%
                </div>
                <div style={s.compLabel}>Compliance Rate</div>
              </div>
            </div>
            {riskSummary?.most_common_failure && (
              <div style={s.compCard('#f97316')}>
                <div style={s.compIcon('#f97316')}>
                  <ShieldAlert size={18} color="#f97316" />
                </div>
                <div>
                  <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f97316', fontFamily: 'var(--font-mono)', marginBottom: '0.15rem' }}>
                    {riskSummary.most_common_failure.replace(/_/g, ' ')}
                  </div>
                  <div style={s.compLabel}>Top Failure</div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* -- Toolbar -- */}
        <div style={s.toolbar}>
          <SearchBar value={search} onChange={(e) => setSearch(e.target.value)} />

          <button style={s.filterBtn(filter === 'all')}      onClick={() => setFilter('all')}>All</button>
          <button style={s.filterBtn(filter === 'online')}   onClick={() => setFilter('online')}>Online</button>
          <button style={s.filterBtn(filter === 'trusted',  '#22c55e')} onClick={() => setFilter('trusted')}>Trusted</button>
          <button style={s.filterBtn(filter === 'warning',  '#eab308')} onClick={() => setFilter('warning')}>Warning</button>
          <button style={s.filterBtn(filter === 'critical', '#ef4444')} onClick={() => setFilter('critical')}>Critical</button>

          <button style={s.refreshBtn} onClick={fetchData}>
            <RefreshCw size={13} /> Refresh
          </button>
          {lastUpdate && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Updated {lastUpdate.toLocaleTimeString()}
            </span>
          )}
        </div>

        {/* -- Machine grid -- */}
        {loading ? (
          <div style={{ color: 'var(--text-muted)', padding: '2rem', textAlign: 'center' }}>
            Loading machines...
          </div>
        ) : (
          <div style={s.grid}>
            {filtered.length === 0 ? (
              <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                No machines found matching your filters.
              </div>
            ) : (
              filtered.map((machine) => (
                <MachineCard
                  key={machine.id}
                  machine={machine}
                  onClick={() => navigate(`/machines/${machine.id}`)}
                />
              ))
            )}
          </div>
        )}

      </main>
    </div>
  )
}