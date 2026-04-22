/**
 * QuietMonitor – api/api.js
 * ─────────────────────────
 * Centralised Axios instance and API call functions.
 * All components import from here – if the base URL ever changes,
 * we update only this file.
 */

import axios from 'axios'

// Base URL points to our FastAPI backend.
// When running via Vite dev server the /api prefix is proxied.
const BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/** Axios instance shared across all requests */
const api = axios.create({
  baseURL: BASE_URL,
  headers: { 'Content-Type': 'application/json' },
})

// ── Request interceptor – attach JWT token to every request ───────
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('qm_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// ── Response interceptor – redirect to login on 401 ──────────────
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('qm_token')
      localStorage.removeItem('qm_role')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// ─────────────────────────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────────────────────────

/** POST /login – returns { access_token, token_type, role } */
export const loginUser = (username, password) =>
  api.post('/login', { username, password })

/** GET /me – returns the current user's profile */
export const getMe = () => api.get('/me')

// ─────────────────────────────────────────────────────────────────
// MACHINES
// ─────────────────────────────────────────────────────────────────

/**
 * GET /machines
 * @param {boolean} onlineOnly  - filter to online machines only
 * @param {string}  search      - hostname search fragment
 */
export const getMachines = (onlineOnly = false, search = '') =>
  api.get('/machines', { params: { online_only: onlineOnly, search } })

/** GET /machines/:id */
export const getMachine = (id) => api.get(`/machines/${id}`)

/** GET /machines/:id/history?limit=n */
export const getMachineHistory = (id, limit = 60) =>
  api.get(`/machines/${id}/history`, { params: { limit } })

// ─────────────────────────────────────────────────────────────────
// ALERTS
// ─────────────────────────────────────────────────────────────────

/** GET /alerts – active (unresolved) alerts */
export const getAlerts = () => api.get('/alerts')

/** GET /alerts/all – full alert history */
export const getAllAlerts = (limit = 200) =>
  api.get('/alerts/all', { params: { limit } })

/** PATCH /alerts/:id/resolve */
export const resolveAlert = (id) =>
  api.patch(`/alerts/${id}/resolve`, { resolved: true })

export default api
