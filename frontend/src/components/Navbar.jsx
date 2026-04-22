/**
 * QuietMonitor – components/Navbar.jsx
 * ──────────────────────────────────────
 * Top navigation bar shown on every authenticated page.
 * Displays:
 *   - Application logo / name
 *   - Current username and role badge
 *   - Logout button
 */

import React from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Monitor, LogOut, Shield } from 'lucide-react'
import { useAuth } from '../App.jsx'

const styles = {
  nav: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 1.5rem',
    height: '60px',
    background: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border)',
    position: 'sticky',
    top: 0,
    zIndex: 100,
  },
  brand: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    textDecoration: 'none',
    color: 'var(--text-primary)',
    fontWeight: 700,
    fontSize: '1.1rem',
    letterSpacing: '-0.02em',
  },
  brandIcon: { color: 'var(--accent-blue)' },
  right: { display: 'flex', alignItems: 'center', gap: '1rem' },
  badge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem',
    fontSize: '0.78rem',
    padding: '0.25rem 0.7rem',
    borderRadius: '999px',
    background: 'rgba(59,130,246,0.15)',
    color: 'var(--accent-blue)',
    fontWeight: 500,
    textTransform: 'capitalize',
  },
  logoutBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    padding: '0.4rem 0.9rem',
    borderRadius: 'var(--radius-sm)',
    border: '1px solid var(--border)',
    background: 'transparent',
    color: 'var(--text-secondary)',
    fontSize: '0.85rem',
    cursor: 'pointer',
    transition: 'all 0.15s',
  },
}

export default function Navbar() {
  const { role, logout } = useAuth()
  const navigate          = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <nav style={styles.nav}>
      {/* Brand */}
      <Link to="/" style={styles.brand}>
        <Monitor size={22} style={styles.brandIcon} />
        QuietMonitor
      </Link>

      {/* Right side */}
      <div style={styles.right}>
        {/* Role badge */}
        <span style={styles.badge}>
          <Shield size={12} />
          {role || 'viewer'}
        </span>

        {/* Logout */}
        <button
          style={styles.logoutBtn}
          onClick={handleLogout}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = 'var(--red)'
            e.currentTarget.style.color       = 'var(--red)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = 'var(--border)'
            e.currentTarget.style.color       = 'var(--text-secondary)'
          }}
        >
          <LogOut size={14} />
          Logout
        </button>
      </div>
    </nav>
  )
}
