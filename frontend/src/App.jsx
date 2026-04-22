/**
 * QuietMonitor – App.jsx
 * ───────────────────────
 * Root component that owns:
 *   - Client-side routing via React Router v6
 *   - Auth state (token + role stored in localStorage)
 *   - A <PrivateRoute> guard that redirects unauthenticated users to /login
 */

import React, { useState, useEffect, createContext, useContext } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'

import Login          from './pages/Login.jsx'
import Dashboard      from './pages/Dashboard.jsx'
import MachineDetail  from './pages/MachineDetail.jsx'
import SecurityPosture from './pages/SecurityPosture.jsx'

// ── Auth Context ──────────────────────────────────────────────────
// Provides { token, role, login(), logout() } to any child component
export const AuthContext = createContext(null)

export function useAuth() {
  return useContext(AuthContext)
}

// ─────────────────────────────────────────────────────────────────
// PRIVATE ROUTE GUARD
// ─────────────────────────────────────────────────────────────────
function PrivateRoute({ children }) {
  const { token } = useAuth()
  const location  = useLocation()

  if (!token) {
    // Redirect to login, preserving the URL the user tried to visit
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return children
}

// ─────────────────────────────────────────────────────────────────
// APP COMPONENT
// ─────────────────────────────────────────────────────────────────
export default function App() {
  // Hydrate auth state from localStorage so the user stays logged in
  // after a page refresh.
  const [token, setToken] = useState(() => localStorage.getItem('qm_token') || null)
  const [role,  setRole]  = useState(() => localStorage.getItem('qm_role')  || null)

  const login = (accessToken, userRole) => {
    localStorage.setItem('qm_token', accessToken)
    localStorage.setItem('qm_role',  userRole)
    setToken(accessToken)
    setRole(userRole)
  }

  const logout = () => {
    localStorage.removeItem('qm_token')
    localStorage.removeItem('qm_role')
    setToken(null)
    setRole(null)
  }

  return (
    <AuthContext.Provider value={{ token, role, login, logout }}>
      <BrowserRouter>
        <Routes>
          {/* Public route */}
          <Route path="/login" element={<Login />} />

          {/* Protected routes */}
          <Route path="/" element={
            <PrivateRoute><Dashboard /></PrivateRoute>
          } />
          <Route path="/machines/:id" element={
            <PrivateRoute><MachineDetail /></PrivateRoute>
          } />
          <Route path="/machines/:id/posture" element={
            <PrivateRoute><SecurityPosture /></PrivateRoute>
          } />

          {/* Catch-all → home */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  )
}
