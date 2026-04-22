/**
 * QuietMonitor â€“ pages/Dashboard.jsx
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 * Zero Trust compliance dashboard.
 *
 * Features:
 *   - Summary stats: Total / Online / Offline / Alerts / Trusted / Warning / Critical
 *   - Active alerts strip (AlertBanner)
 *   - Search + filter (All / Online / Trusted / Warning / Critical)
 *   - Grid of MachineCard components
 *   - Auto-refresh every 30 seconds
 */

import React, { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Server, Wifi, WifiOff, Bell, RefreshCw,
  ShieldCheck, ShieldAlert, ShieldOff,
} from 'lucide-react'

import Navbar       from '../components/Navbar.jsx'
import AlertBanner  from '../components/AlertBanner.jsx'
import MachineCard  from '../components/MachineCard.jsx'
import SearchBar    from '../components/SearchBar.jsx'
import { getMachines, getAlerts, resolveAlert } from '../api/api.js'

const REFRESH_INTERVAL = 30_000

export default function Dashboard() {
  const navigate = useNavigate()

  const [machines,    setMachines]    = useState([])
  const [alerts,      setAlerts]      = useState([])
  const [search,      setSearch]      = useState('')
  const [filter,      setFilter]      = useState('all')   // 'all'|'online'|'trusted'|'warning'|'critical'
  const [loading,     setLoading]     = useState(true)
  const [lastUpdate,  setLastUpdate]  = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [machinesRes, alertsRes] = await Promise.all([getMachines(), getAlerts()])
      setMachines(machinesRes.data)
      setAlerts(alertsRes.data)
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

  // â”€â”€ Derived counts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const online   = machines.filter((m) => m.is_online).length
  const offline  = machines.length - online
  const trusted  = machines.filter((m) => m.trust_level === 'trusted').length
  const warning  = machines.filter((m) => m.trust_level === 'warning').length
  const critical = machines.filter((m) => m.trust_level === 'critical').length

  // â”€â”€ Filtered list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const filtered = machines
    .filter((m) => {
      if (filter === 'online')   return m.is_online
      if (filter === 'trusted')  return m.trust_level === 'trusted'
      if (filter === 'warning')  return m.trust_level === 'warning'
      if (filter === 'critical') return m.trust_level === 'critical'
      return true
    })
    .filter((m) => !search || m.hostname.toLowerCase().includes(search.toLowerCase()))

  // â”€â”€ Styles â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const s = {
    page:  { minHeight: '100vh', background: 'var(--bg-primary)' },
    main:  { padding: '1.5rem', maxWidth: '1400px', margin: '0 auto' },
    statsRow: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
      gap: '0.85rem', marginBottom: '1.5rem',
    },
    statCard: (color) => ({
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 'var(--radius)', padding: '0.9rem 1.1rem',
      display: 'flex', flexDirection: 'column', gap: '0.3rem',
      borderLeft: `3px solid ${color}`,
    }),
    statValue: { fontSize: '1.7rem', fontWeight: 700, lineHeight: 1 },
    statLabel: { fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' },
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

        {/* â”€â”€ Summary stats â”€â”€ */}
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
          {/* Zero Trust trust-level cards */}
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

        {/* â”€â”€ Toolbar â”€â”€ */}
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

        {/* â”€â”€ Machine grid â”€â”€ */}
        {loading ? (
          <div style={{ color: 'var(--text-muted)', padding: '2rem', textAlign: 'center' }}>
            Loading machinesâ€¦
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
