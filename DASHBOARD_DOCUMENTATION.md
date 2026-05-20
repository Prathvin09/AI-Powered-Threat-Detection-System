# 🛡️ SENTINEL v3.0 - Dashboard Documentation

## 📋 Table of Contents

1. [Overview](#1-overview)
2. [System Architecture](#2-system-architecture)
3. [Dashboard Features](#3-dashboard-features)
4. [Tab-by-Tab Guide](#4-tab-by-tab-guide)
5. [API Integration](#5-api-integration)
6. [Real-Time Data Flow](#6-real-time-data-flow)
7. [Threat Detection Display](#7-threat-detection-display)
8. [User Guide](#8-user-guide)
9. [Technical Specifications](#9-technical-specifications)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

### What is SENTINEL Dashboard?

**SENTINEL** is a real-time threat detection and system monitoring dashboard built with **React** and **FastAPI**. It provides comprehensive visibility into system health, network activity, and security threats with AI-powered detection and automated response capabilities.

### Key Capabilities

| Feature | Description |
|---------|-------------|
| **Real-Time Monitoring** | System metrics update every 5 seconds |
| **Threat Detection** | 60+ threat types detected using hybrid AI model |
| **Auto-Response** | Automatic threat mitigation (process suspension, IP blocking) |
| **Packet Inspection** | Deep network packet analysis with protocol detection |
| **Process Monitoring** | Risk-scored process list with behavioral analysis |
| **Health Scoring** | 0-100 system health index |

### Technology Stack

```
┌─────────────────────────────────────────────────────────────┐
│  FRONTEND                    BACKEND                        │
│  ├─ React 18.2.0             ├─ FastAPI 0.115+              │
│  ├─ Recharts 2.10.1          ├─ Uvicorn 0.32+               │
│  ├─ Axios 1.6.2              ├─ psutil 6.1.1+               │
│  └─ JavaScript ES6+          ├─ scapy 2.5+                  │
│                              ├─ scikit-learn 1.5.2+         │
│  DATABASE                    └─ SQLite / MongoDB            │
│  ├─ SQLite 3.x                                              │
│  └─ MongoDB (optional)                                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SENTINEL SYSTEM                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐         ┌──────────────┐         ┌─────────┐ │
│  │   FRONTEND   │  HTTP   │   BACKEND    │  Data   │  AGENT  │ │
│  │   (React)    │ ◄─────► │   (FastAPI)  │ ◄────── │ (Python)│ │
│  │  Port: 3000  │   WS    │  Port: 8000  │ Collect │         │ │
│  └──────────────┘         └──────────────┘         └─────────┘ │
│         │                        │                              │
│         │                        ▼                              │
│         │                 ┌──────────────┐                     │
│         │                 │   DATABASE   │                     │
│         │                 │   (SQLite)   │                     │
│         │                 └──────────────┘                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow Pipeline

```
1. SentinelAgent collects system snapshot (every 5s)
   │
   ├─→ System metrics (CPU, RAM, Disk, Battery)
   ├─→ Process list with risk scores
   ├─→ Network connections
   └─→ Packet capture (scapy)
   │
   ▼
2. EnhancedThreatDetector analyzes data
   │
   ├─→ Rule-based detection (signatures)
   ├─→ ML anomaly detection (Z-score)
   ├─→ Behavioral analysis
   └─→ False positive filtering
   │
   ▼
3. Auto-Response Engine executes actions
   │
   ├─→ SUSPEND_PROCESS
   ├─→ BLOCK_IP
   ├─→ QUARANTINE_FILE
   └─→ EMERGENCY_SHUTDOWN
   │
   ▼
4. Data saved to SQLite database
   │
   ▼
5. FastAPI serves data via REST + WebSocket
   │
   ▼
6. React dashboard displays real-time data
```

---

## 3. Dashboard Features

### 3.1 Main Navigation Tabs

| Tab | Icon | Purpose | Badge |
|-----|------|---------|-------|
| **OVERVIEW** | 📊 | System health at a glance | - |
| **THREATS** | 🚨 | Active & resolved threats | Active count |
| **ANALYTICS** | 📈 | Charts & statistics | - |
| **PACKETS** | 📦 | Network packet inspection | Suspicious count |
| **PROCESSES** | ⚙️ | Running processes with risk | - |
| **NETWORK** | 🌐 | Network connections | - |
| **TIMELINE** | 📅 | Historical threat timeline | - |

### 3.2 Real-Time Indicators

| Indicator | Meaning |
|-----------|---------|
| 🟢 Green Pulse | System normal / Connection active |
| 🔴 Red Pulse | Threat detected / Connection lost |
| 🟠 Orange Pulse | Warning state |
| ⚡ Lightning | Auto-response executed |
| 🔒 Lock | System locked / quarantine active |

### 3.3 Status Colors

| Color | Severity | Meaning |
|-------|----------|---------|
| 🔴 Red (#ef4444) | CRITICAL | Immediate action required |
| 🟠 Orange (#f97316) | HIGH | Urgent attention needed |
| 🟡 Yellow (#eab308) | MEDIUM | Review recommended |
| 🟢 Green (#22c55e) | LOW / SAFE | Normal operation |
| 🔵 Blue (#3b82f6) | INFO | Informational |

---

## 4. Tab-by-Tab Guide

### 4.1 OVERVIEW Tab

#### Purpose
System health summary with key metrics and active threats.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  OVERVIEW                                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐      │
│  │ CPU: 35% │ │ RAM: 58% │ │Disk: 62% │ │Health: 85│      │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ACTIVE THREATS (3)                                 │   │
│  │  ⚠️ CRYPTOMINER - HIGH (92%)                        │   │
│  │  ⚠️ SUSPICIOUS NETWORK - MEDIUM (74%)               │   │
│  │  🔍 ANOMALY DETECTED - MEDIUM (68%)                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [Chart: CPU/RAM usage over time - 40 data points]          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Metrics Explained

| Metric | Source | Update Frequency |
|--------|--------|------------------|
| CPU % | `psutil.cpu_percent()` | Every 5 seconds |
| RAM % | `psutil.virtual_memory()` | Every 5 seconds |
| Disk % | `psutil.disk_usage('/')` | Every 5 seconds |
| Health Score | Calculated (threats + metrics) | Every 5 seconds |
| Active Threats | Database query | Every 5 seconds |

#### Health Score Calculation

```python
def calculate_health_score(metrics, threats):
    score = 100
    score -= len(threats) * 15        # -15 per active threat
    if metrics['avg_cpu'] > 80: score -= 20
    elif metrics['avg_cpu'] > 60: score -= 10
    if metrics['avg_ram'] > 80: score -= 15
    return max(0, min(100, score))
```

---

### 4.2 THREATS Tab

#### Purpose
Centralized threat management center with detailed incident reports.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  THREAT CENTER                                              │
├─────────────────────────────────────────────────────────────┤
│  Filters: [ALL] [ACTIVE] [RESOLVED] [CRITICAL] [HIGH]      │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ TYPE          │ SEVERITY │ CONF  │ TIME    │ STATUS │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ ⛏️ CRYPTOMINER│ 🔴 HIGH  │ 92%   │ 14:32:15│ ACTIVE │   │
│  │ 🌐 NETWORK    │ 🟡 MEDIUM │ 74%   │ 14:20:00│ ACTIVE │   │
│  │ 🔍 ANOMALY    │ 🟡 MEDIUM │ 68%   │ 13:14:00│ ACTIVE │   │
│  │ 🔨 BRUTE FORCE│ 🔴 HIGH  │ 88%   │ Yesterday│RESOLVED│   │
│  │ 🔒 RANSOMWARE │ 🔴 CRIT  │ 97%   │ 2 days  │RESOLVED│   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Statistics:                                                │
│  [TOTAL: 5] [RESOLVED: 2] [AVG CONF: 84%] [CRITICAL: 2]    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Threat Details (Expanded View)

When a threat row is clicked, it expands to show:

```
┌─────────────────────────────────────────────────────────────┐
│  INCIDENT DETAILS                                           │
├─────────────────────────────────────────────────────────────┤
│  Description:                                               │
│  Unknown process "cryptominer64.exe" consuming 91% CPU      │
│  from C:\Users\AppData\Local\Temp                           │
│                                                             │
│  User Message:                                              │
│  Your PC is being secretly used to mine cryptocurrency      │
│  for someone else.                                          │
│                                                             │
│  Detected At: 14:32:15 on 01 Apr 2026                       │
│  Full Timestamp: 2026-04-01T14:32:15.123456                │
│                                                             │
│  RESPONSE ACTIONS (4 steps):                                │
│  1. Process suspended automatically by SENTINEL            │
│  2. Remove cryptominer64.exe from AppData\Temp             │
│  3. Check recently installed software (last 48h)           │
│  4. Scan all browser extensions                            │
│                                                             │
│  [✓ MARK AS RESOLVED]                                       │
└─────────────────────────────────────────────────────────────┘
```

#### Threat Types Supported

| Category | Threat Types |
|----------|--------------|
| **Malware** | CRYPTOMINER, RANSOMWARE, TROJAN, SPYWARE, ROOTKIT |
| **Network** | PORT_SCAN, DNS_TUNNELING, C2_BEACONING, ARP_SPOOFING |
| **Web** | PHISHING, DRIVE_BY_DOWNLOAD, CRYPTOJACKING |
| **Access** | BRUTE_FORCE, BACKDOOR, CREDENTIAL_STUFFING |
| **ML** | ANOMALY_DETECTED |

---

### 4.3 ANALYTICS Tab

#### Purpose
Visual analytics with charts and statistical breakdowns.

#### Charts

**1. Threat Distribution (Pie Chart)**
```
     Cryptominer: 35%
     Network: 25%
     Anomaly: 28%
     Ransomware: 12%
```

**2. Severity Breakdown (Pie Chart)**
```
     Critical: 40%
     High: 40%
     Medium: 20%
     Low: 0%
```

**3. Threat Types (Bar Chart)**
```
     Port Scan:     ████████ 8
     DNS Tunnel:    ████ 4
     C2 Beacon:     ██████ 6
     Susp Port:     █████ 5
```

**4. Protocol Distribution (Pie Chart)**
```
     TCP:   8500 packets (42%)
     UDP:   4200 packets (21%)
     DNS:   2720 packets (14%)
     HTTPS: 4100 packets (20%)
     ICMP:  300 packets (2%)
     HTTP:  600 packets (3%)
```

**5. Weekly Threats (Bar Chart)**
```
     Mon: ██ 2 threats
     Tue: ███ 3 threats
     Wed: █████ 5 threats
     Thu: ███ 3 threats
     Fri: ████ 4 threats
     Sat: ██ 2 threats
     Sun: ███ 3 threats
```

---

### 4.4 PACKETS Tab

#### Purpose
Real-time network packet inspection with protocol analysis.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  PACKET INSPECTION                                          │
├─────────────────────────────────────────────────────────────┤
│  Filters: [ALL] [SUSPICIOUS] [NORMAL]                       │
│  Protocol: [ALL] [TCP] [UDP] [ICMP] [DNS] [HTTP] [HTTPS]   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ PROTO │ SOURCE          │ DESTINATION     │ SIZE   │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ TCP   │ 192.168.1.10:49152│ 8.8.8.8:53    │ 64 B   │   │
│  │ DNS   │ 192.168.1.10:49153│ 1.1.1.1:53    │ 128 B  │   │
│  │ TCP   │ 192.168.1.10:49154│ 185.220.101:4444│ 512 B│   │
│  │       │                 │               │ ⚠ SUSPICIOUS_PORT│
│  │ HTTP  │ 192.168.1.10:49155│ 172.217.14:80 │ 1024 B │   │
│  │ HTTPS │ 192.168.1.10:49156│ 52.96.1.1:443 │ 2048 B │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Showing 120 of 8547 packets | Auto-refresh: 5s            │
│  [Export PCAP - 30s capture]                                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Packet Details

| Field | Description |
|-------|-------------|
| **Protocol** | TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP |
| **Source** | Source IP:Port |
| **Destination** | Destination IP:Port |
| **Size** | Packet size in bytes |
| **Flags** | TCP flags (SYN, ACK, PSH, etc.) |
| **Status** | ✓ NORMAL or ⚠ SUSPICIOUS with threat type |
| **Confidence** | Detection confidence (0-100%) |

#### Suspicious Packet Indicators

| Indicator | Meaning |
|-----------|---------|
| ⚠ SUSPICIOUS_PORT | Connection to known malware port (4444, 6666, 1337) |
| ⚠ PORT_SCAN_DETECTED | Multiple ports scanned in short time |
| ⚠ DNS_TUNNELING | Large DNS query (>512 bytes) |
| ⚠ ICMP_TUNNELING | Oversized ICMP packet (>1000 bytes) |
| ⚠ C2_BEACONING | Regular interval connections (beacon pattern) |
| ⚠ MALICIOUS_IP | Connection to known malicious IP |

---

### 4.5 PROCESSES Tab

#### Purpose
Process monitoring with risk scoring and behavioral analysis.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  PROCESS MONITOR                                            │
├─────────────────────────────────────────────────────────────┤
│  Total: 245 | High Risk: 3 | Medium Risk: 12 | Safe: 230   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ PROCESS         │ PID  │ CPU   │ MEM   │ RISK      │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ chrome.exe      │ 1234 │ 12.3% │ 8.1%  │ 🟢 5      │   │
│  │ python.exe      │ 5678 │ 3.1%  │ 2.4%  │ 🟢 10     │   │
│  │ svchost.exe     │ 9012 │ 1.2%  │ 1.8%  │ 🟢 5      │   │
│  │ unknown.exe     │ 3456 │ 45.6% │ 12.3% │ 🔴 88 ⚠️  │   │
│  │   C:\Users\AppData\Local\Temp\unknown.exe           │   │
│  │ node.exe        │ 7890 │ 5.4%  │ 4.2%  │ 🟢 10     │   │
│  │ explorer.exe    │ 2345 │ 0.8%  │ 1.1%  │ 🟢 5      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Risk Score Calculation

| Factor | Weight | Description |
|--------|--------|-------------|
| Unknown process | +20 | Not in known safe list |
| Suspicious name | +40 | Contains malware keywords |
| High CPU (>80%) | +25 | Resource abuse indicator |
| High CPU (>50%) | +10 | Elevated usage |
| High Memory (>50%) | +15 | Memory abuse |
| Temp path | +30 | Running from suspicious location |

#### Risk Levels

| Score | Color | Action |
|-------|-------|--------|
| 0-40 | 🟢 Green | Safe - known process |
| 41-70 | 🟡 Yellow | Monitor - elevated risk |
| 71-100 | 🔴 Red | Investigate - high risk |

---

### 4.6 NETWORK Tab

#### Purpose
Network connection monitoring with suspicious connection detection.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  NETWORK CONNECTIONS                                        │
├─────────────────────────────────────────────────────────────┤
│  Active: 47 | Suspicious: 3 | Bytes Sent: 1.2 GB | Recv: 3.4 GB │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ LOCAL          │ REMOTE          │ STATUS │ PID    │   │
│  ├─────────────────────────────────────────────────────┤   │
│  │ 192.168.1.10:49152│ 8.8.8.8:53   │ ESTAB  │ 1234  │   │
│  │ 192.168.1.10:49153│ 1.1.1.1:53   │ ESTAB  │ 1234  │   │
│  │ 192.168.1.10:49154│ 185.220.101:4444│ ESTAB│ 3456 ⚠️│
│  │ 192.168.1.10:49155│ 172.217.14:80│ ESTAB  │ 1234  │   │
│  │ 0.0.0.0:80     │ 0.0.0.0:0      │ LISTEN │ 5678  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Connection Status Types

| Status | Meaning |
|--------|---------|
| ESTABLISHED | Active connection |
| LISTEN | Waiting for incoming connection |
| TIME_WAIT | Connection closing |
| CLOSE_WAIT | Remote side closed |
| SYN_SENT | Connection request sent |
| SYN_RECEIVED | Connection request received |

#### Suspicious Connection Indicators

| Indicator | Ports | Meaning |
|-----------|-------|---------|
| Backdoor | 4444, 5555, 6666, 1337, 31337 | Known malware ports |
| IoT Attack | 1883, 8883, 5683 | MQTT/CoAP protocols |
| Database | 1433, 3306, 5432, 27017 | Database access |

---

### 4.7 TIMELINE Tab

#### Purpose
Historical view of detected threats over time.

#### Components

```
┌─────────────────────────────────────────────────────────────┐
│  THREAT TIMELINE                                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Apr 01, 2026                                               │
│  ├─ 14:32:15  ⛏️ CRYPTOMINER (HIGH) - ACTIVE               │
│  ├─ 14:20:00  🌐 SUSPICIOUS NETWORK (MEDIUM) - ACTIVE      │
│  ├─ 13:14:00  🔍 ANOMALY DETECTED (MEDIUM) - ACTIVE        │
│                                                             │
│  Mar 31, 2026                                               │
│  ├─ 23:45:00  🔨 BRUTE FORCE (HIGH) - RESOLVED             │
│  ├─ 18:30:00  🦠 MALWARE (CRITICAL) - RESOLVED             │
│                                                             │
│  Mar 30, 2026                                               │
│  ├─ 15:20:00  🔒 RANSOMWARE (CRITICAL) - RESOLVED          │
│                                                             │
│  Statistics:                                                │
│  Total: 7 | Active: 3 | Resolved: 4 | Critical: 2          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 5. API Integration

### 5.1 Backend Connection

**Base URL:** `http://localhost:8000/api`

### 5.2 REST API Endpoints

| Endpoint | Method | Purpose | Frontend Component |
|----------|--------|---------|-------------------|
| `/metrics/live` | GET | Real-time system metrics | Overview, all tabs |
| `/metrics/history` | GET | Historical metrics | Charts |
| `/processes` | GET | Process list | Processes tab |
| `/network` | GET | Network connections | Network tab |
| `/threats` | GET | All threats | Threats tab |
| `/threats/{id}/resolve` | POST | Resolve threat | Threats tab |
| `/packets/live` | GET | Recent packets | Packets tab |
| `/packets/suspicious` | GET | Suspicious packets | Packets tab |
| `/packets/statistics` | GET | Packet statistics | Analytics tab |
| `/packets/export` | POST | Export PCAP | Packets tab |
| `/auto-response/history` | GET | Auto-response log | Analytics tab |
| `/summary` | GET | System health summary | Overview tab |

### 5.3 WebSocket Connection

**Endpoint:** `ws://localhost:8000/ws/live`

**Purpose:** Real-time data streaming (updates every 5 seconds)

**Message Format:**
```json
{
  "type": "LIVE_UPDATE",
  "cpu": 35,
  "ram": 58,
  "disk": 62,
  "network_in": 3400000000,
  "network_out": 1200000000,
  "status": "WARNING",
  "anomaly_score": 0.32,
  "new_threats": [...],
  "timestamp": "2026-04-01T14:32:15.123456"
}
```

### 5.4 Frontend API Calls

```javascript
const API = "http://localhost:8000/api";

// Fetch live metrics
const metricsRes = await fetch(`${API}/metrics/live`);
const metricsData = await metricsRes.json();

// Fetch threats
const threatsRes = await fetch(`${API}/threats`);
const threatsData = await threatsRes.json();

// Resolve threat
await fetch(`${API}/threats/${threatId}/resolve`, { method: 'POST' });

// WebSocket connection
const ws = new WebSocket("ws://localhost:8000/ws/live");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Update UI with real-time data
};
```

---

## 6. Real-Time Data Flow

### 6.1 Update Cycle

```
┌─────────────────────────────────────────────────────────────┐
│  DATA UPDATE CYCLE (5 seconds)                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  T+0s:   Agent collects system snapshot                     │
│  T+0.1s: Detector analyzes for threats                      │
│  T+0.2s: Auto-response executes (if needed)                 │
│  T+0.3s: Data saved to database                             │
│  T+0.4s: FastAPI sends response                             │
│  T+0.5s: React dashboard updates UI                         │
│                                                             │
│  T+5s:   Cycle repeats                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Data Refresh Strategy

| Data Type | Refresh Method | Frequency |
|-----------|----------------|-----------|
| System Metrics | HTTP Polling + WebSocket | Every 5 seconds |
| Threats | HTTP Polling | Every 5 seconds |
| Processes | HTTP on-demand | On tab switch |
| Packets | HTTP Polling | Every 5 seconds |
| Network | HTTP on-demand | On tab switch |
| Charts | Calculated from fetched data | Every 5 seconds |

---

## 7. Threat Detection Display

### 7.1 Threat Card Format

```
┌─────────────────────────────────────────────────────────────┐
│  ⛏️ CRYPTOMINER_DETECTED                                    │
│  ════════════════════════════════════════════════════════  │
│  Severity:    🔴 HIGH                                       │
│  Confidence:  92%                                           │
│  Detected:    14:32:15 (3 minutes ago)                      │
│  Status:      ACTIVE                                        │
│                                                             │
│  Description:                                               │
│  Unknown process "cryptominer64.exe" consuming 91% CPU      │
│  from C:\Users\AppData\Local\Temp                           │
│                                                             │
│  User Message:                                              │
│  Your PC is being secretly used to mine cryptocurrency      │
│  for someone else.                                          │
│                                                             │
│  Auto-Response Executed:                                    │
│  ✅ Process suspended automatically by SENTINEL             │
│                                                             │
│  Recommended Actions:                                       │
│  1. Remove cryptominer64.exe from Temp folder              │
│  2. Check recently installed software                      │
│  3. Scan browser extensions                                │
│  4. Change account passwords                               │
│                                                             │
│  [✓ MARK AS RESOLVED]                                       │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Threat Severity Levels

| Severity | Color | Auto-Response | Example |
|----------|-------|---------------|---------|
| CRITICAL | 🔴 Red | EMERGENCY_SHUTDOWN | Ransomware, Wiper |
| HIGH | 🟠 Orange | SUSPEND_PROCESS | Cryptominer, Backdoor |
| MEDIUM | 🟡 Yellow | ALERT_ONLY | Anomaly, Suspicious Network |
| LOW | 🟢 Green | LOG_ONLY | Info, Minor Policy Violation |

### 7.3 MITRE ATT&CK Mapping

Some threats display MITRE ATT&CK technique IDs:

| Threat Type | MITRE ID | Technique |
|-------------|----------|-----------|
| PORT_SCAN | T1046 | Network Service Scanning |
| DNS_TUNNELING | T1071.004 | Application Layer Protocol: DNS |
| ICMP_TUNNELING | T1095 | Non-Application Layer Protocol |
| C2_BEACONING | T1071 | Application Layer Protocol |
| ARP_SPOOFING | T1557 | Adversary-in-the-Middle |

---

## 8. User Guide

### 8.1 Getting Started

1. **Start Backend:**
   ```bash
   cd "c:\Users\ASUS\OneDrive\Desktop\THREAT DETECTOR"
   .venv\Scripts\python.exe -m uvicorn backend.server:app --reload --port 8000
   ```

2. **Start Frontend:**
   ```bash
   cd frontend
   npm start
   ```

3. **Access Dashboard:**
   - Open browser to `http://localhost:3000`
   - Dashboard will connect to backend automatically

### 8.2 Daily Operations

| Task | Steps |
|------|-------|
| **Check System Health** | View OVERVIEW tab, check health score |
| **Review Threats** | Go to THREATS tab, review active threats |
| **Resolve Threat** | Click threat → Review details → Click "MARK AS RESOLVED" |
| **Monitor Network** | Go to PACKETS tab, filter by SUSPICIOUS |
| **Export Evidence** | PACKETS tab → Click "EXPORT PCAP" |
| **View History** | Go to TIMELINE tab, review past threats |

### 8.3 Interpreting Alerts

| Alert | Action |
|-------|--------|
| 🔴 Health Score < 50 | Immediate investigation required |
| 🔴 Active Threats > 3 | Critical state - review all threats |
| 🟠 CPU > 80% sustained | Check for cryptominer |
| 🟠 Suspicious Packets > 10 | Review network activity |
| 🟡 Unknown Processes | Investigate high-risk processes |

### 8.4 Best Practices

1. **Monitor Daily:** Check dashboard at least once per day
2. **Resolve Promptly:** Mark resolved threats to keep view clean
3. **Export Evidence:** Save PCAP files for forensic analysis
4. **Review Trends:** Check ANALYTICS weekly for patterns
5. **Update Baselines:** Allow ML model to learn normal behavior (100 samples)

---

## 9. Technical Specifications

### 9.1 Performance Metrics

| Metric | Value |
|--------|-------|
| Update Frequency | 5 seconds |
| Detection Latency | < 500ms (signature), < 2s (ML) |
| False Positive Rate | < 10% (with filtering) |
| Memory Usage | ~50-100 MB |
| CPU Overhead | ~2-5% |
| Supported OS | Windows 10/11 |

### 9.2 Database Schema

**Tables:**
- `metrics` - System metrics history
- `processes` - Process snapshots
- `threats` - Detected threats
- `network_events` - Network connections
- `packet_events` - Captured packets
- `auto_response_history` - Auto-response log
- `quarantine` - Quarantined files

### 9.3 Frontend Components

| Component | File | Purpose |
|-----------|------|---------|
| Main Dashboard | `App.jsx` | Primary UI, all tabs |
| Packet Analysis | `PacketAnalysis.jsx` | Dedicated packet view |
| Charts | Recharts | Data visualization |

### 9.4 Browser Requirements

| Browser | Minimum Version |
|---------|-----------------|
| Chrome | 90+ |
| Firefox | 88+ |
| Edge | 90+ |
| Safari | 14+ |

---

## 10. Troubleshooting

### 10.1 Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| **Dashboard not loading** | Backend not running | Start backend with `uvicorn` |
| **No data showing** | Backend connection failed | Check if backend is on port 8000 |
| **WebSocket disconnected** | Port conflict | Ensure port 8000 is not in use |
| **Packets not showing** | Scapy not installed | Run `pip install scapy` |
| **Permission denied** | Admin rights needed | Run as Administrator |
| **High CPU usage** | Full packet capture | Enable lightweight mode |

### 10.2 Debug Commands

```bash
# Check if backend is running
curl http://localhost:8000/

# Check database
sqlite3 sentinel.db "SELECT * FROM threats LIMIT 5;"

# Check Python processes
tasklist | findstr python

# Check port usage
netstat -ano | findstr :8000
```

### 10.3 Log Files

| Log | Location |
|-----|----------|
| Backend Logs | Console output (terminal) |
| Frontend Logs | Browser DevTools Console |
| Database | `sentinel.db` |
| PCAP Files | `pcap_captures/` folder |

---

## Appendix A: Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + R` | Refresh dashboard |
| `Ctrl + F` | Search threats |
| `Esc` | Close expanded threat |

---

## Appendix B: Color Reference

| Color | Hex Code | Usage |
|-------|----------|-------|
| Primary Blue | `#3b82f6` | TCP, default |
| Success Green | `#22c55e` | UDP, safe, resolved |
| Warning Yellow | `#eab308` | DNS, medium severity |
| Danger Red | `#ef4444` | ICMP, critical, threats |
| Info Cyan | `#06b6d4` | HTTP, info |
| Purple | `#8b5cf6` | HTTPS |
| Pink | `#ec4899` | ARP |
| Slate | `#64748b` | Other, unknown |

---

## Appendix C: Threat Response Matrix

| Threat Type | Auto-Action | Manual Steps |
|-------------|-------------|--------------|
| CRYPTOMINER | SUSPEND_PROCESS | Remove file, scan extensions |
| RANSOMWARE | EMERGENCY_SHUTDOWN | Disconnect network, restore backup |
| BRUTE_FORCE | LOCKDOWN | Change password, enable 2FA |
| BACKDOOR | SUSPEND_PROCESS + BLOCK_IP | Full system scan |
| DATA_EXFILTRATION | ISOLATE_AND_ALERT | Identify source, block destination |
| ANOMALY | ALERT_ONLY | Monitor, investigate |

---

## Appendix D: Version Information

| Component | Version |
|-----------|---------|
| SENTINEL | 3.0.0 |
| Frontend | 1.0.0 |
| Backend API | 1.0.0 |
| Database Schema | 2.0 |

---

**Document Created:** April 1, 2026  
**Last Updated:** April 1, 2026  
**Author:** SENTINEL Development Team

---

*For educational and project demonstration purposes.*
