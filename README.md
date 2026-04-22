# QuietMonitor 🖥️

> **Internal IT Monitoring Dashboard** — track Windows machine health in real time from a clean, modern web interface.

![Stack](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)
![Stack](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB?style=flat-square&logo=react)
![Stack](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite)
![Stack](https://img.shields.io/badge/Agent-PowerShell-5391FE?style=flat-square&logo=powershell)

---

## 📋 Features

| Feature | Details |
|---|---|
| **Live Dashboard** | Machine cards with CPU / RAM / Disk gauges |
| **Status colours** | 🟢 Healthy · 🟡 Warning · 🔴 Critical · ⚫ Offline |
| **Alerts** | High CPU, low disk, offline machines, AV disabled |
| **History** | Recharts line graphs for the last 60 metric snapshots |
| **Search & filter** | By hostname, online-only toggle |
| **Authentication** | JWT with role-based access (admin / viewer) |
| **PowerShell agent** | Auto-registers the host, runs every 5 minutes |

---

## 🗂️ Project Structure

```
quietmonitor/
├── backend/
│   ├── app/
│   │   ├── main.py          ← FastAPI app, startup, CORS
│   │   ├── database.py      ← SQLAlchemy engine & session
│   │   ├── models.py        ← ORM models (users, machines, metrics, alerts)
│   │   ├── schemas.py       ← Pydantic request/response schemas
│   │   ├── auth.py          ← JWT & bcrypt helpers, route dependencies
│   │   ├── utils.py         ← Thresholds & helper functions
│   │   ├── routes/
│   │   │   ├── machines.py  ← GET /machines, POST /agent/update
│   │   │   ├── auth.py      ← POST /login, GET /me
│   │   │   └── alerts.py    ← GET /alerts, PATCH /alerts/:id/resolve
│   │   └── services/
│   │       ├── machine_service.py  ← upsert, list, history logic
│   │       └── alert_service.py   ← threshold evaluation, alert CRUD
│   ├── requirements.txt
│   └── .env
│
├── frontend/
│   ├── src/
│   │   ├── api/api.js           ← Axios instance + all API calls
│   │   ├── components/
│   │   │   ├── Navbar.jsx
│   │   │   ├── MachineCard.jsx
│   │   │   ├── AlertBanner.jsx
│   │   │   └── SearchBar.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── MachineDetail.jsx
│   │   │   └── Login.jsx
│   │   ├── App.jsx              ← Router + AuthContext
│   │   └── main.jsx
│   ├── vite.config.js
│   └── package.json
│
├── agents/
│   └── windows_agent.ps1        ← PowerShell heartbeat agent
│
└── README.md
```

---

## 🚀 Quick Start

### 1 — Clone & set up the backend

```bash
cd backend

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # macOS / Linux

# Install dependencies
pip install -r requirements.txt

# Start the API server
uvicorn app.main:app --reload --port 8000
```

The first start will:
- Create `quietmonitor.db` (SQLite file)
- Seed a default **admin** account: `admin` / `admin123`

API docs: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### 2 — Set up the frontend

```bash
cd frontend

npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) and sign in with `admin` / `admin123`.

---

### 3 — Deploy the PowerShell agent

1. Copy `agents/windows_agent.ps1` to each Windows machine you want to monitor.
2. Edit the `$BackendUrl` variable at the top of the script:
   ```powershell
   $BackendUrl = "http://YOUR_SERVER_IP:8000/agent/update"
   ```
3. Run it manually to test:
   ```powershell
   powershell -ExecutionPolicy Bypass -File windows_agent.ps1
   ```
4. Schedule it via **Task Scheduler** to run every 5 minutes:
   ```powershell
   $action  = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"C:\Path\windows_agent.ps1`""
   $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
   Register-ScheduledTask -TaskName "QuietMonitorAgent" -Action $action -Trigger $trigger -RunLevel Highest
   ```

---

## 🔑 API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/login` | ❌ | Exchange credentials for JWT |
| `GET` | `/me` | ✅ | Current user profile |
| `POST` | `/agent/update` | ❌ | Agent heartbeat (machine data) |
| `GET` | `/machines` | ✅ | List all machines |
| `GET` | `/machines/{id}` | ✅ | Single machine details |
| `GET` | `/machines/{id}/history` | ✅ | Metric history |
| `GET` | `/alerts` | ✅ | Active (unresolved) alerts |
| `GET` | `/alerts/all` | ✅ | All alerts (with resolved) |
| `PATCH` | `/alerts/{id}/resolve` | ✅ | Resolve an alert |

---

## ⚙️ Configuration

### Backend `.env`

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `supersecretkey_…` | JWT signing key — **change in production** |
| `ALGORITHM` | `HS256` | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Token TTL |
| `DATABASE_URL` | `sqlite:///./quietmonitor.db` | SQLAlchemy DB URL |
| `CORS_ORIGINS` | `http://localhost:5173` | Allowed frontend origins |

---

## 🚨 Alert Thresholds

| Metric | Warning | Critical |
|---|---|---|
| CPU Usage | ≥ 80% | ≥ 95% |
| RAM Usage | ≥ 85% | ≥ 95% |
| Disk Usage | ≥ 85% | ≥ 95% |
| Antivirus | — | Disabled / Not found |
| Offline | — | > 10 min without check-in |

---

## 🛡️ Security Notes

- Change `SECRET_KEY` in `.env` before any production deployment.
- Change the default `admin123` password immediately after first login.
- The `/agent/update` endpoint is intentionally unauthenticated to allow
  agents to self-register. Consider adding a shared API-key header in production.
- Use HTTPS (reverse proxy with Nginx/Caddy) when running outside localhost.

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11 · FastAPI · SQLAlchemy · Uvicorn |
| Auth | JWT (python-jose) · bcrypt (passlib) |
| Database | SQLite (swap to PostgreSQL with one URL change) |
| Frontend | React 18 · Vite · React Router v6 |
| Charts | Recharts |
| Icons | Lucide React |
| Agent | PowerShell 5.1+ |

---

## 📄 License

MIT — free to use and modify for personal, educational, and commercial projects.
