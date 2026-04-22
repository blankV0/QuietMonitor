/**
 * QuietMonitor – components/SearchBar.jsx
 * ─────────────────────────────────────────
 * Reusable search input with a magnifier icon.
 * Props:
 *   value     – controlled input value
 *   onChange  – callback (event) => void
 *   placeholder
 */

import React from 'react'
import { Search } from 'lucide-react'

const styles = {
  wrapper: {
    position: 'relative',
    display: 'inline-flex',
    alignItems: 'center',
  },
  icon: {
    position: 'absolute',
    left: '0.75rem',
    color: 'var(--text-muted)',
    pointerEvents: 'none',
  },
  input: {
    background: 'var(--bg-card)',
    border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)',
    color: 'var(--text-primary)',
    fontSize: '0.9rem',
    padding: '0.55rem 0.9rem 0.55rem 2.25rem',
    width: '280px',
    outline: 'none',
    transition: 'border-color 0.15s',
  },
}

export default function SearchBar({ value, onChange, placeholder = 'Search machines…' }) {
  return (
    <div style={styles.wrapper}>
      <Search size={15} style={styles.icon} />
      <input
        type="text"
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        style={styles.input}
        onFocus={(e)  => (e.target.style.borderColor = 'var(--accent-blue)')}
        onBlur={(e)   => (e.target.style.borderColor = 'var(--border)')}
      />
    </div>
  )
}
