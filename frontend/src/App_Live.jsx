import { useState, useEffect } from "react";
import {
  AreaChart, Area, LineChart, Line, BarChart, Bar,
  PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Legend
} from "recharts";

const API = "http://localhost:8000/api";

// ─── THREAT TYPES ────────────────────────────────────────────────────────────
const THREAT_TYPES = [
  { type: "CRYPTOMINER_DETECTED", icon: "⛏️", color: "#f97316", sev: "HIGH" },
  { type: "RANSOMWARE_DETECTED", icon: "🔒", color: "#ef4444", sev: "CRITICAL" },
  { type: "TROJAN_DETECTED", icon: "🐴", color: "#ef4444", sev: "CRITICAL" },
  { type: "SPYWARE_DETECTED", icon: "👁️", color: "#f97316", sev: "HIGH" },
  { type: "ROOTKIT_DETECTED", icon: "🔧", color: "#ef4444", sev: "CRITICAL" },
  { type: "FILELESS_MALWARE_DETECTED", icon: "👻", color: "#ef4444", sev: "CRITICAL" },
  { type: "SQL_INJECTION_EXPLOITATION", icon: "💉", color: "#ef4444", sev: "CRITICAL" },
  { type: "FORMJACKING_DETECTED", icon: "🛒", color: "#ef4444", sev: "CRITICAL" },
  { type: "DATA_EXFILTRATION_INDICATOR", icon: "📤", color: "#ef4444", sev: "CRITICAL" },
  { type: "BRUTE_FORCE_ATTACK", icon: "🔨", color: "#f97316", sev: "HIGH" },
  { type: "DDOS_ATTACK_INDICATOR", icon: "🌊", color: "#f97316", sev: "HIGH" },
  { type: "ANOMALY", icon: "🔍", color: "#eab308", sev: "MEDIUM" },
];

// ─── CUSTOM TOOLTIP ───────────────────────────────────────────────────────────
const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background: "#0a0f1e", border: "1px solid #1e3a5f", borderRadius: 10, padding: "10px 14px", fontSize: 11, fontFamily: "'JetBrains Mono',monospace" }}>
      <p style={{ color: "#64748b", marginBottom: 6, letterSpacing: 1 }}>{label}</p>
      {payload.map((p, i) => (
        <p key={i} style={{ color: p.color, marginBottom: 2 }}>
          {p.name}: <span style={{ color: "#e2e8f0", fontWeight: 700 }}>{typeof p.value === "number" ? p.value.toFixed(1) : p.value}</span>
        </p>
      ))}
    </div>
  );
};

// ─── PULSE RING ───────────────────────────────────────────────────────────────
function PulseRing({ color, size = 10 }) {
  return (
    <span style={{ position: "relative", display: "inline-flex", alignItems: "center", justifyContent: "center", width: size, height: size }}>
      <span style={{ position: "absolute", width: "100%", height: "100%", borderRadius: "50%", background: color, opacity: 0.4, animation: "ping 1.5s cubic-bezier(0,0,0.2,1) infinite" }} />
      <span style={{ width: size * 0.55, height: size * 0.55, borderRadius: "50%", background: color, display: "block" }} />
    </span>
  );
}

// ─── METRIC CARD ─────────────────────────────────────────────────────────────
function MetricCard({ label, value, icon, color, sublabel }) {
  const v = Math.min(100, Math.max(0, value || 0));
  const barColor = v > 85 ? "#ef4444" : v > 65 ? "#f97316" : color;
  return (
    <div style={{ background: "linear-gradient(135deg,#0a0f1e 0%,#0d1526 100%)", border: `1px solid ${barColor}25`, borderRadius: 20, padding: 24, position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", top: -20, right: -20, width: 100, height: 100, borderRadius: "50%", background: `radial-gradient(circle, ${barColor}12 0%, transparent 70%)` }} />
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 16 }}>
        <div>
          <p style={{ fontSize: 10, color: "#475569", letterSpacing: 3, marginBottom: 6, fontFamily: "'JetBrains Mono',monospace" }}>{label}</p>
          <p style={{ fontSize: 36, fontWeight: 900, color: barColor, lineHeight: 1, fontFamily: "'JetBrains Mono',monospace" }}>{v.toFixed(1)}%</p>
        </div>
        <div style={{ width: 44, height: 44, borderRadius: 12, background: `${barColor}15`, border: `1px solid ${barColor}30`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 20 }}>{icon}</div>
      </div>
      <div style={{ height: 4, background: "#0f1929", borderRadius: 999, overflow: "hidden" }}>
        <div style={{ height: "100%", width: `${v}%`, background: `linear-gradient(90deg, ${barColor}80, ${barColor})`, borderRadius: 999, boxShadow: `0 0 12px ${barColor}60` }} />
      </div>
      <p style={{ fontSize: 10, color: "#334155", marginTop: 8, fontFamily: "'JetBrains Mono',monospace" }}>{sublabel}</p>
    </div>
  );
}

// ─── THREAT ROW ───────────────────────────────────────────────────────────────
function ThreatRow({ threat, onResolve, expanded, onExpand }) {
  const sevColor = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e" };
  const c = sevColor[threat.severity] || "#eab308";
  const timeAgo = (iso) => {
    const m = Math.floor((Date.now() - new Date(iso)) / 60000);
    return m < 1 ? "just now" : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m / 60)}h ago` : `${Math.floor(m / 1440)}d ago`;
  };

  return (
    <>
      <tr style={{ borderBottom: "1px solid #0d1526", cursor: "pointer" }} onClick={() => onExpand(threat.id)}>
        <td style={{ padding: "14px 16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <PulseRing color={threat.status === "ACTIVE" ? c : "#334155"} size={8} />
            <span style={{ fontSize: 18 }}>{threat.icon || "⚠️"}</span>
            <span style={{ color: "#e2e8f0", fontWeight: 600, fontSize: 12, fontFamily: "'JetBrains Mono',monospace" }}>{threat.type}</span>
          </div>
        </td>
        <td style={{ padding: "14px 16px" }}>
          <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 999, fontWeight: 700, letterSpacing: 1, background: `${c}18`, color: c, border: `1px solid ${c}30` }}>{threat.severity}</span>
        </td>
        <td style={{ padding: "14px 16px" }}>
          <span style={{ fontSize: 11, color: c, fontWeight: 700, fontFamily: "'JetBrains Mono',monospace" }}>{threat.confidence}%</span>
        </td>
        <td style={{ padding: "14px 16px", color: "#475569", fontSize: 11, fontFamily: "'JetBrains Mono',monospace" }}>{timeAgo(threat.detected_at)}</td>
        <td style={{ padding: "14px 16px" }}>
          <span style={{ fontSize: 9, padding: "3px 10px", borderRadius: 999, fontWeight: 700, letterSpacing: 1, background: threat.status === "ACTIVE" ? "rgba(239,68,68,0.1)" : "rgba(34,197,94,0.1)", color: threat.status === "ACTIVE" ? "#ef4444" : "#22c55e", border: `1px solid ${threat.status === "ACTIVE" ? "rgba(239,68,68,0.2)" : "rgba(34,197,94,0.2)"}` }}>{threat.status}</span>
        </td>
        <td style={{ padding: "14px 16px", color: "#334155", fontSize: 12 }}>{expanded ? "▲" : "▼"}</td>
      </tr>
      {expanded && (
        <tr style={{ background: "#060a14" }}>
          <td colSpan={6} style={{ padding: "0 16px 16px" }}>
            <div style={{ background: "#0a0f1e", border: "1px solid #1e3a5f", borderRadius: 12, padding: 20 }}>
              <p style={{ fontSize: 9, color: "#475569", letterSpacing: 3, marginBottom: 8 }}>⚡ INCIDENT SUMMARY</p>
              <p style={{ color: "#94a3b8", fontSize: 12, lineHeight: 1.6 }}>{threat.description}</p>
              {threat.user_message && (
                <div style={{ marginTop: 12, padding: 12, background: "#060a14", borderRadius: 8, borderLeft: `3px solid ${c}` }}>
                  <p style={{ color: "#cbd5e1", fontSize: 12 }}>{threat.user_message}</p>
                </div>
              )}
              {threat.preventive_steps && threat.preventive_steps.length > 0 && (
                <>
                  <p style={{ fontSize: 9, color: "#475569", letterSpacing: 3, marginTop: 16, marginBottom: 8 }}>🛡️ RESPONSE ACTIONS</p>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    {threat.preventive_steps.map((s, i) => (
                      <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                        <span style={{ minWidth: 20, height: 20, borderRadius: 6, background: `${c}18`, color: c, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 900, border: `1px solid ${c}25` }}>{i + 1}</span>
                        <span style={{ color: "#94a3b8", fontSize: 11, lineHeight: 1.5 }}>{s}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
              {threat.status === "ACTIVE" && (
                <button
                  onClick={(e) => { e.stopPropagation(); onResolve(threat.id); }}
                  style={{ marginTop: 14, padding: "8px 20px", borderRadius: 8, background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.25)", color: "#22c55e", fontSize: 11, fontWeight: 700, cursor: "pointer", letterSpacing: 1, fontFamily: "'JetBrains Mono',monospace" }}
                >
                  ✓ MARK AS RESOLVED
                </button>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ─── PROCESS ROW ──────────────────────────────────────────────────────────────
function ProcRow({ p }) {
  const rc = p.risk > 70 ? "#ef4444" : p.risk > 40 ? "#f97316" : "#22c55e";
  return (
    <tr style={{ borderBottom: "1px solid #0d1526" }}>
      <td style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: rc, boxShadow: `0 0 6px ${rc}` }} />
          <span style={{ color: "#e2e8f0", fontSize: 12, fontFamily: "'JetBrains Mono',monospace" }}>{p.name}</span>
          {!p.is_known && <span style={{ fontSize: 8, background: "rgba(249,115,22,0.15)", color: "#f97316", padding: "2px 6px", borderRadius: 4, fontWeight: 700, border: "1px solid rgba(249,115,22,0.2)", letterSpacing: 1 }}>UNKNOWN</span>}
        </div>
        <p style={{ fontSize: 9, color: "#1e3a5f", marginTop: 2, marginLeft: 14, fontFamily: "'JetBrains Mono',monospace" }}>{p.exe_path || "Unknown"}</p>
      </td>
      <td style={{ padding: "12px 16px", color: "#334155", fontSize: 11, fontFamily: "'JetBrains Mono',monospace", textAlign: "right" }}>{p.pid}</td>
      <td style={{ padding: "12px 16px", textAlign: "right" }}>
        <span style={{ color: p.cpu_percent > 60 ? "#ef4444" : p.cpu_percent > 30 ? "#f97316" : "#94a3b8", fontWeight: 600, fontSize: 12, fontFamily: "'JetBrains Mono',monospace" }}>{p.cpu_percent?.toFixed(1) || 0}%</span>
      </td>
      <td style={{ padding: "12px 16px", color: "#94a3b8", fontSize: 12, fontFamily: "'JetBrains Mono',monospace", textAlign: "right" }}>{p.memory_percent?.toFixed(1) || 0}%</td>
      <td style={{ padding: "12px 16px", textAlign: "right" }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 50, height: 4, background: "#0f1929", borderRadius: 999, overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${p.risk_score || 0}%`, background: `linear-gradient(90deg,${rc}60,${rc})`, borderRadius: 999 }} />
          </div>
          <span style={{ fontSize: 11, fontWeight: 700, color: rc, fontFamily: "'JetBrains Mono',monospace", minWidth: 24 }}>{p.risk_score || 0}</span>
        </div>
      </td>
    </tr>
  );
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
export default function App() {
  const [tab, setTab] = useState("overview");
  const [metrics, setMetrics] = useState({ system: { cpu_percent: 0, ram_percent: 0, disk_percent: 0 }, network: { bytes_sent: 0, bytes_recv: 0, active_connections: 0 }, detection: { system_status: "SAFE", anomaly_score: 0 } });
  const [history, setHistory] = useState([]);
  const [threats, setThreats] = useState([]);
  const [processes, setProcesses] = useState([]);
  const [expanded, setExpanded] = useState(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);

  // Fetch live data from backend
  const fetchLiveData = async () => {
    try {
      const r = await fetch(`${API}/metrics/live`);
      if (!r.ok) throw new Error();
      const d = await r.json();
      setMetrics({
        system: d.system,
        network: d.network,
        detection: d.detection
      });
      setHistory(prev => [...prev, {
        time: new Date().toLocaleTimeString(),
        cpu: d.system.cpu_percent,
        ram: d.system.ram_percent,
        disk: d.system.disk_percent,
        net: (d.network.bytes_sent + d.network.bytes_recv) / 1000000
      }].slice(-40));
      setConnected(true);
      setLoading(false);
    } catch {
      setConnected(false);
      setLoading(false);
    }
  };

  const fetchThreats = async () => {
    try {
      const r = await fetch(`${API}/threats`);
      if (r.ok) {
        const d = await r.json();
        setThreats(d.threats || []);
      }
    } catch (err) {
      console.error("Failed to fetch threats:", err);
    }
  };

  const fetchProcesses = async () => {
    try {
      const r = await fetch(`${API}/processes`);
      if (r.ok) {
        const d = await r.json();
        setProcesses(d.processes || []);
      }
    } catch (err) {
      console.error("Failed to fetch processes:", err);
    }
  };

  useEffect(() => {
    fetchLiveData();
    fetchThreats();
    fetchProcesses();
    const id = setInterval(() => {
      fetchLiveData();
      fetchThreats();
      fetchProcesses();
    }, 4000);
    return () => clearInterval(id);
  }, []);

  const resolveThreat = async (id) => {
    try {
      await fetch(`${API}/threats/${id}/resolve`, { method: "POST" });
      setThreats(prev => prev.map(t => t.id === id ? { ...t, status: "RESOLVED" } : t));
    } catch (err) {
      console.error("Failed to resolve threat:", err);
    }
  };

  const activeThreats = threats.filter(t => t.status === "ACTIVE");
  const healthScore = Math.max(0, 100 - activeThreats.length * 15 - (metrics.system.cpu_percent > 80 ? 20 : 0) - (metrics.system.ram_percent > 85 ? 10 : 0));
  const statusColor = { SAFE: "#22c55e", WARNING: "#f97316", CRITICAL: "#ef4444", CAUTION: "#eab308" };
  const sc = statusColor[metrics.detection.system_status] || "#f97316";

  const TABS = [
    { id: "overview", icon: "◈", label: "Overview" },
    { id: "threats", icon: "⚠", label: "Threats", badge: activeThreats.length },
    { id: "processes", icon: "⚙", label: "Processes" },
  ];

  if (loading) {
    return (
      <div style={{ minHeight: "100vh", background: "#04080f", color: "#e2e8f0", display: "flex", alignItems: "center", justifyContent: "center", fontFamily: "'JetBrains Mono',monospace" }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: 48, marginBottom: 16 }}>🛡️</div>
          <p style={{ fontSize: 14, letterSpacing: 3 }}>SENTINEL</p>
          <p style={{ fontSize: 10, color: "#334155", marginTop: 8 }}>Loading live data...</p>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", background: "#04080f", color: "#e2e8f0", fontFamily: "'JetBrains Mono',monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800;900&family=Orbitron:wght@700;900&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:#04080f;overflow-x:hidden;}
        @keyframes ping{75%,100%{transform:scale(2);opacity:0}}
        ::-webkit-scrollbar{width:3px;height:3px}
        ::-webkit-scrollbar-track{background:#04080f}
        ::-webkit-scrollbar-thumb{background:#1e3a5f;border-radius:2px}
      `}</style>

      {/* Header */}
      <header style={{ background: "rgba(4,8,15,0.98)", borderBottom: "1px solid #0d1e33", padding: "0 24px", height: 60, display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, zIndex: 50 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: "linear-gradient(135deg,#1e3a5f,#0d1e33)", border: "1px solid #1e3a5f", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🛡️</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 900, letterSpacing: 6, color: "#e2e8f0", fontFamily: "'Orbitron',monospace" }}>SENTINEL</div>
            <div style={{ fontSize: 8, color: "#1e3a5f", letterSpacing: 4 }}>LIVE FEED</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 14px", background: "#0a0f1e", border: "1px solid #0d1e33", borderRadius: 10 }}>
            <span style={{ fontSize: 9, color: "#334155", letterSpacing: 2 }}>HEALTH</span>
            <span style={{ fontSize: 14, fontWeight: 900, color: healthScore > 70 ? "#22c55e" : healthScore > 40 ? "#f97316" : "#ef4444" }}>{healthScore}%</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 14px", background: `${sc}10`, border: `1px solid ${sc}30`, borderRadius: 10 }}>
            <PulseRing color={sc} size={8} />
            <span style={{ fontSize: 10, fontWeight: 700, color: sc, letterSpacing: 3 }}>{metrics.detection.system_status}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 9, color: "#334155", letterSpacing: 1 }}>
            <PulseRing color={connected ? "#22c55e" : "#f97316"} size={6} />
            {connected ? "LIVE" : "DISCONNECTED"}
          </div>
        </div>
      </header>

      {/* Navigation */}
      <div style={{ display: "flex", borderBottom: "1px solid #0d1e33", background: "#04080f" }}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              display: "flex", alignItems: "center", gap: 8,
              padding: "16px 24px",
              background: tab === t.id ? "rgba(30,58,95,0.3)" : "transparent",
              border: "none",
              borderBottom: tab === t.id ? "2px solid #3b82f6" : "2px solid transparent",
              color: tab === t.id ? "#60a5fa" : "#334155",
              cursor: "pointer",
              fontSize: 11,
              letterSpacing: 2,
              fontFamily: "'JetBrains Mono',monospace"
            }}
          >
            <span style={{ fontSize: 14 }}>{t.icon}</span>
            <span>{t.label}</span>
            {t.badge > 0 && <span style={{ background: "#ef4444", color: "#fff", borderRadius: 999, minWidth: 18, height: 18, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9, fontWeight: 900 }}>{t.badge}</span>}
          </button>
        ))}
      </div>

      {/* Main Content */}
      <div style={{ padding: 24 }}>
        {/* OVERVIEW TAB */}
        {tab === "overview" && (
          <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
            {/* Metric Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16 }}>
              <MetricCard label="CPU USAGE" value={metrics.system.cpu_percent} icon="🖥️" color="#3b82f6" sublabel={`${metrics.system.cpu_percent.toFixed(1)}% of ${navigator.hardwareConcurrency || 4} cores`} />
              <MetricCard label="RAM USAGE" value={metrics.system.ram_percent} icon="💾" color="#8b5cf6" sublabel={`${((metrics.system.ram_percent / 100) * 16).toFixed(1)} GB / 16 GB`} />
              <MetricCard label="DISK USAGE" value={metrics.system.disk_percent} icon="💿" color="#06b6d4" sublabel="C:\\ Primary Drive" />
              <MetricCard label="NETWORK" value={(metrics.network.bytes_sent + metrics.network.bytes_recv) / 10000000} icon="🌐" color="#22c55e" sublabel={`${metrics.network.active_connections} active connections`} />
            </div>

            {/* Charts */}
            <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
              <div style={{ background: "#0a0f1e", border: "1px solid #0d1e33", borderRadius: 20, padding: 20 }}>
                <p style={{ fontSize: 10, color: "#334155", letterSpacing: 3, marginBottom: 16 }}>REAL-TIME SYSTEM METRICS</p>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={history}>
                    <defs>
                      <linearGradient id="gcpu" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.2} />
                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#0d1e33" />
                    <XAxis dataKey="time" tick={{ fill: "#1e3a5f", fontSize: 8 }} interval={7} />
                    <YAxis domain={[0, 100]} tick={{ fill: "#1e3a5f", fontSize: 8 }} />
                    <Tooltip content={<CustomTooltip />} />
                    <Area type="monotone" dataKey="cpu" stroke="#3b82f6" fill="url(#gcpu)" strokeWidth={1.5} dot={false} />
                    <Area type="monotone" dataKey="ram" stroke="#8b5cf6" fill="url(#gcpu)" strokeWidth={1.5} dot={false} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              {/* Threat Status */}
              <div style={{ background: "#0a0f1e", border: "1px solid #0d1e33", borderRadius: 20, padding: 20 }}>
                <p style={{ fontSize: 10, color: "#334155", letterSpacing: 3, marginBottom: 16 }}>THREAT STATUS</p>
                <div style={{ textAlign: "center", padding: "40px 0" }}>
                  <div style={{ fontSize: 48, marginBottom: 16 }}>{activeThreats.length > 0 ? "⚠️" : "✅"}</div>
                  <p style={{ fontSize: 24, fontWeight: 900, color: activeThreats.length > 0 ? "#ef4444" : "#22c55e" }}>{activeThreats.length}</p>
                  <p style={{ fontSize: 10, color: "#334155", marginTop: 8 }}>ACTIVE THREATS</p>
                  <p style={{ fontSize: 12, color: "#94a3b8", marginTop: 4 }}>{threats.length} TOTAL</p>
                </div>
              </div>
            </div>

            {/* Active Threats Preview */}
            {activeThreats.length > 0 && (
              <div style={{ background: "#0a0f1e", border: "1px solid rgba(239,68,68,0.2)", borderRadius: 20, padding: 20 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                    <PulseRing color="#ef4444" size={8} />
                    <span style={{ fontSize: 10, fontWeight: 700, color: "#ef4444", letterSpacing: 3 }}>ACTIVE THREATS</span>
                  </div>
                  <button onClick={() => setTab("threats")} style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.2)", color: "#60a5fa", padding: "6px 14px", borderRadius: 8, fontSize: 10, cursor: "pointer", fontFamily: "'JetBrains Mono',monospace" }}>VIEW ALL →</button>
                </div>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #0d1e33" }}>
                      {["THREAT", "SEVERITY", "CONFIDENCE", "TIME", "STATUS", ""].map(h => (
                        <th key={h} style={{ padding: "8px 16px", fontSize: 9, color: "#1e3a5f", letterSpacing: 2, textAlign: "left", fontWeight: 700 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeThreats.slice(0, 3).map(t => (
                      <ThreatRow key={t.id} threat={t} onResolve={resolveThreat} expanded={expanded === t.id} onExpand={setExpanded} />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* THREATS TAB */}
        {tab === "threats" && (
          <div>
            <div style={{ marginBottom: 20 }}>
              <h2 style={{ fontSize: 16, fontWeight: 900, letterSpacing: 4, fontFamily: "'Orbitron',monospace", color: "#e2e8f0" }}>THREAT CENTER</h2>
              <p style={{ fontSize: 10, color: "#334155", marginTop: 4, letterSpacing: 2 }}>{activeThreats.length} ACTIVE · {threats.filter(t => t.status === "RESOLVED").length} RESOLVED</p>
            </div>
            <div style={{ background: "#0a0f1e", border: "1px solid #0d1e33", borderRadius: 20, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #0d1e33", background: "#04080f" }}>
                    {["THREAT TYPE", "SEVERITY", "CONFIDENCE", "DETECTED", "STATUS", ""].map(h => (
                      <th key={h} style={{ padding: "12px 16px", fontSize: 9, color: "#1e3a5f", letterSpacing: 2, textAlign: "left", fontWeight: 700 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {threats.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: "center", padding: "60px 0", color: "#1e3a5f" }}>
                        <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
                        <p style={{ fontSize: 12, letterSpacing: 2 }}>NO THREATS DETECTED</p>
                      </td>
                    </tr>
                  ) : (
                    threats.map(t => (
                      <ThreatRow key={t.id} threat={t} onResolve={resolveThreat} expanded={expanded === t.id} onExpand={setExpanded} />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* PROCESSES TAB */}
        {tab === "processes" && (
          <div>
            <div style={{ marginBottom: 20 }}>
              <h2 style={{ fontSize: 16, fontWeight: 900, letterSpacing: 4, fontFamily: "'Orbitron',monospace", color: "#e2e8f0" }}>PROCESS MONITOR</h2>
              <p style={{ fontSize: 10, color: "#334155", marginTop: 4, letterSpacing: 2 }}>{processes.filter(p => p.risk_score > 70).length} HIGH RISK · {processes.length} TOTAL</p>
            </div>
            <div style={{ background: "#0a0f1e", border: "1px solid #0d1e33", borderRadius: 20, overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid #0d1e33", background: "#04080f" }}>
                    {["PROCESS NAME", "PID", "CPU %", "RAM %", "RISK SCORE"].map((h, i) => (
                      <th key={h} style={{ padding: "12px 16px", fontSize: 9, color: "#1e3a5f", letterSpacing: 2, textAlign: i === 0 ? "left" : "right", fontWeight: 700 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {processes.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 50).map((p, i) => (
                    <ProcRow key={i} p={p} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer style={{ borderTop: "1px solid #0d1e33", padding: "10px 24px", display: "flex", justifyContent: "space-between", fontSize: 9, color: "#1e3a5f", letterSpacing: 2, background: "#04080f" }}>
        <span>SENTINEL v2.1 · LIVE THREAT DETECTION</span>
        <span>UPDATED: {new Date().toLocaleTimeString()} · {connected ? "BACKEND CONNECTED" : "DISCONNECTED"}</span>
      </footer>
    </div>
  );
}
