/**
 * QuietMonitor – pages/Login.jsx
 * ───────────────────────────────
 * Public login page.
 * On successful authentication the JWT token and role are stored via
 * the AuthContext and the user is redirected to the dashboard.
 */

import React, { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Monitor, Lock, User, Eye, EyeOff } from 'lucide-react'
import { loginUser } from '../api/api.js'
import { useAuth } from '../App.jsx'

export default function Login() {
  const [username,    setUsername]    = useState('')
  const [password,    setPassword]    = useState('')
  const [showPwd,     setShowPwd]     = useState(false)
  const [error,       setError]       = useState('')
  const [loading,     setLoading]     = useState(false)

  const { login }   = useAuth()
  const navigate    = useNavigate()
  const location    = useLocation()
  const from        = location.state?.from?.pathname || '/'

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const { data } = await loginUser(username, password)
      login(data.access_token, data.role)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  // ── Styles ────────────────────────────────────────────────────
  const s = {
    page: {
      minHeight: '100vh', display: 'flex', alignItems: 'center',
      justifyContent: 'center', background: 'var(--bg-primary)',
      padding: '1rem',
    },
    card: {
      width: '100%', maxWidth: '400px',
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius)',
      padding: '2.5rem 2rem',
    },
    logo: {
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      gap: '0.6rem', marginBottom: '2rem',
      color: 'var(--text-primary)', fontSize: '1.4rem', fontWeight: 700,
    },
    logoIcon: { color: 'var(--accent-blue)' },
    subtitle: {
      textAlign: 'center', color: 'var(--text-secondary)',
      fontSize: '0.85rem', marginTop: '-1.5rem', marginBottom: '2rem',
    },
    label: {
      display: 'block', fontSize: '0.82rem', fontWeight: 500,
      color: 'var(--text-secondary)', marginBottom: '0.4rem',
    },
    inputWrap: { position: 'relative', marginBottom: '1rem' },
    inputIcon: {
      position: 'absolute', left: '0.75rem', top: '50%',
      transform: 'translateY(-50%)', color: 'var(--text-muted)',
      pointerEvents: 'none',
    },
    input: {
      width: '100%', background: 'var(--bg-secondary)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)',
      fontSize: '0.9rem', padding: '0.65rem 0.9rem 0.65rem 2.3rem',
      outline: 'none', transition: 'border-color 0.15s',
    },
    eyeBtn: {
      position: 'absolute', right: '0.75rem', top: '50%',
      transform: 'translateY(-50%)', background: 'none', border: 'none',
      color: 'var(--text-muted)', cursor: 'pointer',
    },
    error: {
      background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
      borderRadius: 'var(--radius-sm)', padding: '0.6rem 0.9rem',
      color: 'var(--red)', fontSize: '0.83rem', marginBottom: '1rem',
    },
    submitBtn: {
      width: '100%', padding: '0.7rem',
      background: 'var(--accent-blue)', color: '#fff',
      border: 'none', borderRadius: 'var(--radius-sm)',
      fontSize: '0.95rem', fontWeight: 600, cursor: 'pointer',
      transition: 'background 0.15s', opacity: loading ? 0.7 : 1,
    },
    hint: {
      textAlign: 'center', marginTop: '1.5rem',
      fontSize: '0.75rem', color: 'var(--text-muted)',
    },
  }

  return (
    <div style={s.page}>
      <div style={s.card}>
        {/* Logo */}
        <div style={s.logo}>
          <Monitor size={28} style={s.logoIcon} />
          QuietMonitor
        </div>
        <p style={s.subtitle}>Internal IT Monitoring Dashboard</p>

        <form onSubmit={handleSubmit}>
          {/* Username */}
          <label style={s.label}>Username</label>
          <div style={s.inputWrap}>
            <User size={15} style={s.inputIcon} />
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={s.input}
              placeholder="admin"
              autoFocus
              required
              onFocus={(e) => (e.target.style.borderColor = 'var(--accent-blue)')}
              onBlur={(e)  => (e.target.style.borderColor = 'var(--border)')}
            />
          </div>

          {/* Password */}
          <label style={s.label}>Password</label>
          <div style={s.inputWrap}>
            <Lock size={15} style={s.inputIcon} />
            <input
              type={showPwd ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={s.input}
              placeholder="••••••••"
              required
              onFocus={(e) => (e.target.style.borderColor = 'var(--accent-blue)')}
              onBlur={(e)  => (e.target.style.borderColor = 'var(--border)')}
            />
            <button type="button" style={s.eyeBtn} onClick={() => setShowPwd((p) => !p)}>
              {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>

          {/* Error */}
          {error && <div style={s.error}>{error}</div>}

          {/* Submit */}
          <button
            type="submit"
            style={s.submitBtn}
            disabled={loading}
            onMouseEnter={(e) => !loading && (e.target.style.background = 'var(--accent-blue-hover)')}
            onMouseLeave={(e) => (e.target.style.background = 'var(--accent-blue)')}
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>

        <p style={s.hint}>Default: admin / admin123 — change after first login</p>
      </div>
    </div>
  )
}
