import { useState, useEffect } from "react";
import { BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const API = "http://localhost:8000/api";

const COLORS = {
    primary: "#3b82f6",
    success: "#22c55e",
    warning: "#eab308",
    danger: "#ef4444",
    info: "#06b6d4",
    dark: "#0a1020"
};

const SEVERITY_COLORS = {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#22c55e"
};

function fmtTime(ts) {
    if (!ts) return "--:--:--";
    try {
        return new Date(ts).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    } catch {
        return ts;
    }
}

function PacketRow({ packet }) {
    const isSuspicious = packet.is_suspicious;
    const protocolColor = {
        'TCP': '#3b82f6',
        'UDP': '#22c55e',
        'ICMP': '#f97316',
        'DNS': '#eab308',
        'HTTP': '#06b6d4',
        'HTTPS': '#8b5cf6',
        'ARP': '#ec4899',
        'OTHER': '#64748b'
    }[packet.protocol] || '#64748b';

    return (
        <tr style={{
            borderBottom: "1px solid #060e18",
            background: isSuspicious ? "rgba(239,68,68,0.05)" : "transparent",
            transition: "background 0.12s"
        }}
            onMouseEnter={e => e.currentTarget.style.background = isSuspicious ? "rgba(239,68,68,0.08)" : "rgba(30,58,95,0.08)"}
            onMouseLeave={e => e.currentTarget.style.background = isSuspicious ? "rgba(239,68,68,0.05)" : "transparent"}
        >
            <td style={{ padding: "10px 14px" }}>
                <span style={{
                    fontSize: 9,
                    fontWeight: 700,
                    color: protocolColor,
                    padding: "2px 8px",
                    borderRadius: 4,
                    background: `${protocolColor}12`,
                    border: `1px solid ${protocolColor}25`
                }}>
                    {packet.protocol}
                </span>
            </td>
            <td style={{ padding: "10px 14px", fontSize: 9, color: "#94a3b8" }}>
                {packet.src_ip || "—"}
                {packet.src_port && <span style={{ color: "#475569", marginLeft: 4 }}>: {packet.src_port}</span>}
            </td>
            <td style={{ padding: "10px 14px", fontSize: 9, color: "#94a3b8" }}>
                {packet.dst_ip || "—"}
                {packet.dst_port && <span style={{ color: "#475569", marginLeft: 4 }}>: {packet.dst_port}</span>}
            </td>
            <td style={{ padding: "10px 14px", fontSize: 9, color: "#475569", textAlign: "right" }}>
                {packet.length} B
            </td>
            <td style={{ padding: "10px 14px" }}>
                <span style={{ fontSize: 8, color: "#1a3050" }}>{fmtTime(packet.timestamp)}</span>
            </td>
            <td style={{ padding: "10px 14px", textAlign: "right" }}>
                {isSuspicious ? (
                    <span style={{
                        fontSize: 7,
                        padding: "2px 8px",
                        borderRadius: 4,
                        fontWeight: 700,
                        background: "rgba(239,68,68,0.12)",
                        color: "#ef4444",
                        border: "1px solid rgba(239,68,68,0.25)",
                        letterSpacing: 1
                    }}>
                        ⚠ {packet.threat_type || 'SUSPICIOUS'}
                    </span>
                ) : (
                    <span style={{ fontSize: 7, color: "#22c55e" }}>✓ Normal</span>
                )}
            </td>
        </tr>
    );
}

function StatCard({ label, value, icon, color, subtext }) {
    return (
        <div style={{
            background: "linear-gradient(150deg,#0a1020,#07101c)",
            border: "1px solid #0e1d33",
            borderRadius: 14,
            padding: 16,
            position: "relative",
            overflow: "hidden"
        }}>
            <div style={{ position: "absolute", top: -12, right: -12, width: 50, height: 50, borderRadius: "50%", background: `radial-gradient(circle,${color}08,transparent)` }} />
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 10 }}>
                <span style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2 }}>{label}</span>
                <span style={{ fontSize: 14 }}>{icon}</span>
            </div>
            <div style={{ fontSize: 24, fontWeight: 900, color: color, lineHeight: 1 }}>{value}</div>
            {subtext && <div style={{ fontSize: 7, color: "#0d1e33", marginTop: 4 }}>{subtext}</div>}
        </div>
    );
}

export function PacketAnalysis() {
    const [packets, setPackets] = useState([]);
    const [suspicious, setSuspicious] = useState([]);
    const [stats, setStats] = useState(null);
    const [analysis, setAnalysis] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState("ALL"); // ALL, SUSPICIOUS, NORMAL
    const [protocolFilter, setProtocolFilter] = useState("ALL");

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [packetsRes, suspiciousRes, statsRes, analysisRes] = await Promise.all([
                    fetch(`${API}/packets/live?limit=100`),
                    fetch(`${API}/packets/suspicious?limit=50`),
                    fetch(`${API}/packets/statistics`),
                    fetch(`${API}/packets/analysis`)
                ]);

                const packetsData = await packetsRes.json();
                const suspiciousData = await suspiciousRes.json();
                const statsData = await statsRes.json();
                const analysisData = await analysisRes.json();

                setPackets(packetsData.packets || []);
                setSuspicious(suspiciousData.packets || []);
                setStats(statsData);
                setAnalysis(analysisData);
                setLoading(false);
            } catch (error) {
                console.error("Error fetching packet data:", error);
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 5000);
        return () => clearInterval(interval);
    }, []);

    // Prepare protocol distribution for pie chart
    const protocolData = analysis?.protocol_distribution
        ? Object.entries(analysis.protocol_distribution).map(([name, value]) => ({
            name,
            value,
            color: {
                'TCP': '#3b82f6',
                'UDP': '#22c55e',
                'ICMP': '#f97316',
                'DNS': '#eab308',
                'HTTP': '#06b6d4',
                'HTTPS': '#8b5cf6',
                'ARP': '#ec4899',
                'OTHER': '#64748b'
            }[name] || '#64748b'
        }))
        : [];

    // Prepare threat types for bar chart
    const threatData = analysis?.threat_summary?.threats
        ? Object.entries(analysis.threat_summary.threats).map(([name, value]) => ({
            name: name.replace(/_/g, ' '),
            value
        }))
        : [];

    // Filter packets
    const filteredPackets = packets.filter(p => {
        const matchFilter = filter === "ALL"
            ? true
            : filter === "SUSPICIOUS"
                ? p.is_suspicious
                : !p.is_suspicious;

        const matchProtocol = protocolFilter === "ALL" || p.protocol === protocolFilter;

        return matchFilter && matchProtocol;
    });

    const captureStatus = analysis?.capture_status || {};

    return (
        <div style={{ padding: "20px" }}>
            {/* Header */}
            <div style={{ marginBottom: 24 }}>
                <h1 style={{ fontSize: 18, fontWeight: 900, color: "#c8d8f0", marginBottom: 4, fontFamily: "'Syne',sans-serif", letterSpacing: 2 }}>
                    📊 PACKET ANALYSIS
                </h1>
                <p style={{ fontSize: 9, color: "#475569" }}>
                    Real-time network packet inspection and threat detection
                </p>
            </div>

            {/* Status Banner */}
            <div style={{
                padding: "12px 16px",
                background: captureStatus.enabled ? "rgba(34,197,94,0.05)" : "rgba(249,115,22,0.05)",
                border: `1px solid ${captureStatus.enabled ? "rgba(34,197,94,0.15)" : "rgba(249,115,22,0.15)"}`,
                borderRadius: 10,
                marginBottom: 20,
                display: "flex",
                alignItems: "center",
                gap: 12
            }}>
                <div style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: captureStatus.enabled ? "#22c55e" : "#f97316",
                    animation: "pulse 2s infinite"
                }} />
                <span style={{ fontSize: 8, color: captureStatus.enabled ? "#22c55e" : "#f97316", letterSpacing: 2 }}>
                    PACKET INSPECTION: {captureStatus.enabled ? (captureStatus.running ? "ACTIVE" : "STOPPED") : "DISABLED"}
                </span>
                {captureStatus.running && (
                    <span style={{ fontSize: 7, color: "#475569", marginLeft: "auto" }}>
                        Sample Rate: {(captureStatus.sample_rate * 100).toFixed(0)}% | Mode: {captureStatus.lightweight_mode ? "Lightweight" : "Full"}
                    </span>
                )}
            </div>

            {/* Stats Cards */}
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 14, marginBottom: 20 }}>
                <StatCard
                    label="TOTAL PACKETS"
                    value={stats?.live_capture?.total_captured?.toLocaleString() || "0"}
                    icon="📦"
                    color="#3b82f6"
                    subtext="Captured since start"
                />
                <StatCard
                    label="SUSPICIOUS"
                    value={stats?.live_capture?.suspicious_count?.toLocaleString() || "0"}
                    icon="⚠️"
                    color="#ef4444"
                    subtext="Flagged for review"
                />
                <StatCard
                    label="THREATS DETECTED"
                    value={analysis?.threat_summary?.total_suspicious || "0"}
                    icon="🚨"
                    color="#f97316"
                    subtext="Active threats"
                />
                <StatCard
                    label="PROTOCOLS"
                    value={Object.keys(analysis?.protocol_distribution || {}).length}
                    icon="🔷"
                    color="#eab308"
                    subtext="Unique protocols"
                />
            </div>

            {/* Charts Row */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14, marginBottom: 20 }}>
                {/* Protocol Distribution */}
                <div style={{
                    background: "linear-gradient(150deg,#0a1020,#07101c)",
                    border: "1px solid #0e1d33",
                    borderRadius: 14,
                    padding: 16
                }}>
                    <div style={{ fontSize: 8, color: "#1a3050", letterSpacing: 2, marginBottom: 12 }}>
                        PROTOCOL DISTRIBUTION
                    </div>
                    {protocolData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={180}>
                            <PieChart>
                                <Pie
                                    data={protocolData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={50}
                                    outerRadius={80}
                                    paddingAngle={2}
                                    dataKey="value"
                                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                                    labelLine={false}
                                    fontSize={9}
                                >
                                    {protocolData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={entry.color} />
                                    ))}
                                </Pie>
                                <Tooltip
                                    contentStyle={{
                                        background: "#060e18",
                                        border: "1px solid #0e1d33",
                                        borderRadius: 8,
                                        fontSize: 9
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                    ) : (
                        <div style={{
                            height: 180,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: "#475569",
                            fontSize: 9
                        }}>
                            No packet data available
                        </div>
                    )}
                </div>

                {/* Threat Types */}
                <div style={{
                    background: "linear-gradient(150deg,#0a1020,#07101c)",
                    border: "1px solid #0e1d33",
                    borderRadius: 14,
                    padding: 16
                }}>
                    <div style={{ fontSize: 8, color: "#1a3050", letterSpacing: 2, marginBottom: 12 }}>
                        THREAT TYPES DETECTED
                    </div>
                    {threatData.length > 0 ? (
                        <ResponsiveContainer width="100%" height={180}>
                            <BarChart data={threatData}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#0e1d33" />
                                <XAxis
                                    dataKey="name"
                                    stroke="#475569"
                                    fontSize={8}
                                    angle={-45}
                                    textAnchor="end"
                                    height={60}
                                />
                                <YAxis stroke="#475569" fontSize={8} />
                                <Tooltip
                                    contentStyle={{
                                        background: "#060e18",
                                        border: "1px solid #0e1d33",
                                        borderRadius: 8,
                                        fontSize: 9
                                    }}
                                />
                                <Bar dataKey="value" fill="#ef4444" radius={[4, 4, 0, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    ) : (
                        <div style={{
                            height: 180,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "center",
                            color: "#22c55e",
                            fontSize: 9
                        }}>
                            ✓ No threats detected
                        </div>
                    )}
                </div>
            </div>

            {/* Suspicious Packets Alert */}
            {suspicious.length > 0 && (
                <div style={{
                    background: "rgba(239,68,68,0.05)",
                    border: "1px solid rgba(239,68,68,0.15)",
                    borderRadius: 12,
                    padding: 16,
                    marginBottom: 20
                }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                        <span style={{ fontSize: 14 }}>🚨</span>
                        <span style={{ fontSize: 9, color: "#ef4444", fontWeight: 700, letterSpacing: 2 }}>
                            RECENT SUSPICIOUS ACTIVITY ({suspicious.length})
                        </span>
                    </div>
                    <div style={{ display: "grid", gap: 8 }}>
                        {suspicious.slice(0, 5).map((packet, idx) => (
                            <div key={idx} style={{
                                background: "#060e18",
                                border: "1px solid rgba(239,68,68,0.15)",
                                borderRadius: 8,
                                padding: "10px 12px",
                                display: "flex",
                                alignItems: "center",
                                gap: 12
                            }}>
                                <span style={{ fontSize: 7, padding: "2px 6px", borderRadius: 4, background: "rgba(239,68,68,0.12)", color: "#ef4444", fontWeight: 700 }}>
                                    {packet.threat_type || 'SUSPICIOUS'}
                                </span>
                                <span style={{ fontSize: 8, color: "#94a3b8" }}>
                                    {packet.src_ip} → {packet.dst_ip}
                                </span>
                                <span style={{ fontSize: 7, color: "#475569", marginLeft: "auto" }}>
                                    {fmtTime(packet.timestamp)}
                                </span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Filters */}
            <div style={{
                display: "flex",
                gap: 10,
                marginBottom: 14,
                alignItems: "center"
            }}>
                <span style={{ fontSize: 8, color: "#1a3050", letterSpacing: 2 }}>FILTER:</span>
                {["ALL", "SUSPICIOUS", "NORMAL"].map(f => (
                    <button
                        key={f}
                        onClick={() => setFilter(f)}
                        style={{
                            padding: "6px 14px",
                            borderRadius: 6,
                            border: filter === f ? `1px solid ${f === "SUSPICIOUS" ? "#ef4444" : f === "NORMAL" ? "#22c55e" : "#3b82f6"}` : "1px solid #0e1d33",
                            background: filter === f
                                ? f === "SUSPICIOUS" ? "rgba(239,68,68,0.12)"
                                    : f === "NORMAL" ? "rgba(34,197,94,0.12)"
                                        : "rgba(59,130,246,0.12)"
                                : "transparent",
                            color: filter === f
                                ? f === "SUSPICIOUS" ? "#ef4444"
                                    : f === "NORMAL" ? "#22c55e"
                                        : "#3b82f6"
                                : "#475569",
                            fontSize: 7,
                            fontWeight: 700,
                            letterSpacing: 1.5,
                            cursor: "pointer",
                            fontFamily: "'JetBrains Mono',monospace"
                        }}
                    >
                        {f}
                    </button>
                ))}
                <span style={{ fontSize: 8, color: "#1a3050", letterSpacing: 2, marginLeft: 16 }}>PROTOCOL:</span>
                {["ALL", "TCP", "UDP", "ICMP", "DNS", "HTTP", "HTTPS", "ARP"].map(p => (
                    <button
                        key={p}
                        onClick={() => setProtocolFilter(p)}
                        style={{
                            padding: "6px 14px",
                            borderRadius: 6,
                            border: protocolFilter === p ? "1px solid #3b82f6" : "1px solid #0e1d33",
                            background: protocolFilter === p ? "rgba(59,130,246,0.12)" : "transparent",
                            color: protocolFilter === p ? "#3b82f6" : "#475569",
                            fontSize: 7,
                            fontWeight: 700,
                            letterSpacing: 1.5,
                            cursor: "pointer",
                            fontFamily: "'JetBrains Mono',monospace"
                        }}
                    >
                        {p}
                    </button>
                ))}
                <span style={{ fontSize: 7, color: "#475569", marginLeft: "auto" }}>
                    Showing {filteredPackets.length} of {packets.length} packets
                </span>
            </div>

            {/* Packet Table */}
            <div style={{
                background: "linear-gradient(150deg,#0a1020,#07101c)",
                border: "1px solid #0e1d33",
                borderRadius: 14,
                overflow: "hidden"
            }}>
                <div style={{
                    padding: "14px 16px",
                    borderBottom: "1px solid #0e1d33",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between"
                }}>
                    <span style={{ fontSize: 8, color: "#1a3050", letterSpacing: 2 }}>
                        LIVE PACKET STREAM
                    </span>
                    <span style={{ fontSize: 7, color: "#475569" }}>
                        Auto-refreshing every 5s
                    </span>
                </div>
                <div style={{ maxHeight: 400, overflowY: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                        <thead>
                            <tr style={{ borderBottom: "2px solid #0e1d33" }}>
                                <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>PROTOCOL</th>
                                <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>SOURCE</th>
                                <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>DESTINATION</th>
                                <th style={{ padding: "10px 14px", textAlign: "right", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>SIZE</th>
                                <th style={{ padding: "10px 14px", textAlign: "left", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>TIME</th>
                                <th style={{ padding: "10px 14px", textAlign: "right", fontSize: 7, color: "#1a3050", letterSpacing: 1.5, fontWeight: 700 }}>STATUS</th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredPackets.length > 0 ? (
                                filteredPackets.map((packet, idx) => (
                                    <PacketRow key={idx} packet={packet} />
                                ))
                            ) : (
                                <tr>
                                    <td colSpan={6} style={{ padding: 40, textAlign: "center", color: "#475569", fontSize: 9 }}>
                                        {loading ? "Loading packet data..." : "No packets captured yet"}
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Export PCAP */}
            <div style={{ marginTop: 20, textAlign: "right" }}>
                <button
                    onClick={async () => {
                        try {
                            const response = await fetch(`${API}/packets/export?duration=30`, { method: 'POST' });
                            const result = await response.json();
                            alert(result.status === 'success'
                                ? `PCAP saved to: ${result.file}`
                                : `Error: ${result.error}`
                            );
                        } catch (error) {
                            alert(`Error exporting PCAP: ${error.message}`);
                        }
                    }}
                    style={{
                        padding: "10px 20px",
                        borderRadius: 8,
                        border: "1px solid #3b82f6",
                        background: "rgba(59,130,246,0.12)",
                        color: "#3b82f6",
                        fontSize: 8,
                        fontWeight: 700,
                        letterSpacing: 2,
                        cursor: "pointer",
                        fontFamily: "'JetBrains Mono',monospace"
                    }}
                >
                    📥 EXPORT PCAP (30s)
                </button>
            </div>
        </div>
    );
}
