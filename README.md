# 🛡️ SENTINEL — AI-Powered Endpoint Threat Detection System

> Final Year Project | 24x7 PC Monitoring + Unknown Threat Detection + Auto Response

---

## 📖 Documentation
- [Detailed Project Flow & Technical Logic](file:///c:/Users/ASUS/OneDrive/Desktop/THREAT%20DETECTOR/PROJECT_FLOW_DETAILED.md) — *Every minute detail of how SENTINEL works.*

---

## 🚀 Quick Setup (12 Minutes)

### Step 1 — Install Python dependencies
```bash
cd sentinel
pip install -r requirements.txt
```

### Step 2 — Install Frontend dependencies
```bash
cd frontend
npm install
```

### Step 3 — Start the Backend
```bash
# From sentinel/ folder
python -m uvicorn backend.server:app --reload --port 8000
```

### Step 4 — Start the Dashboard
```bash
# In a new terminal, from sentinel/frontend/
npm start
```

### Step 5 — Open Dashboard
```
http://localhost:3000
```

---s

## 📁 Project Structure

```
sentinel/
├── agent/
│   └── collector.py          # Collects CPU, RAM, Network, Process data
├── ml_engine/
│   └── detector.py           # ML anomaly detection + Rule engine
├── database/
│   └── db_manager.py         # SQLite database operations
├── backend/
│   └── server.py             # FastAPI REST API + WebSocket
├── frontend/
│   └── src/
│       └── App.jsx           # React dashboard
├── requirements.txt
├── run.py                    # Start everything
└── README.md
```

---

## 🔍 How Threat Detection Works

### 3 Layers of Detection:

**Layer 1 — Rule Engine (Instant)**
- Cryptominer: Unknown process + CPU > 80%
- Suspicious Network: Connections on unusual ports
- High Risk Process: Process risk score > 70
- Memory Exhaustion: RAM > 95%

**Layer 2 — ML Anomaly Detection**
- Learns YOUR PC's normal behavior over 20+ samples
- Uses statistical baseline (simulates Isolation Forest)
- Flags anything that deviates significantly
- Anomaly score > 0.75 = threat alert

**Layer 3 — Signature Check**
- Checks process names against known malware keywords
- Flags suspicious file paths (temp directories)

---

## 📊 API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/metrics/live` | Current system metrics |
| `GET /api/metrics/history` | Historical data for charts |
| `GET /api/processes` | Running processes with risk scores |
| `GET /api/network` | Network connections |
| `GET /api/threats` | All detected threats |
| `POST /api/threats/{id}/resolve` | Mark threat as resolved |
| `GET /api/summary` | Overall health summary |
| `WS /ws/live` | WebSocket for real-time streaming |

---

## 🛡️ Preventive Response System

When a threat is detected:
1. **Classify** — What type of threat is it?
2. **Score** — How severe is it?
3. **Auto-action** — Suspend process / Block IP / Alert
4. **Notify** — Dashboard alert + desktop notification
5. **Guide** — Step-by-step instructions for user
6. **Log** — Full incident saved to database

---

## 🎓 Presentation Points

- **Problem**: Traditional antivirus only detects KNOWN threats
- **Solution**: Behavioral analysis detects UNKNOWN threats
- **Uniqueness**: Learns YOUR specific PC's normal behavior
- **Impact**: Real-world applicable, comparable to CrowdStrike/SentinelOne
- **Future**: Extend to multi-device, cloud dashboard, mobile alerts

---

## 📚 Tech Stack

| Component | Technology |
|---|---|
| Agent | Python 3.11 + psutil |
| Detection | Rule Engine + Isolation Forest (scikit-learn) |
| Database | SQLite + SQLAlchemy |
| Backend | FastAPI + WebSockets |
| Frontend | React + Recharts + Tailwind CSS |
| Alerts | Email (SMTP) + Desktop notifications |
