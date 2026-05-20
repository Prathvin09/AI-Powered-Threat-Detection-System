import { useState, useEffect } from "react";
import { AreaChart, Area, LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";

const API = "http://localhost:8000/api";
const PROTO_COLORS = { TCP: "#3b82f6", UDP: "#8b5cf6", DNS: "#22d3ee", ICMP: "#f97316", HTTPS: "#22c55e", HTTP: "#eab308", ARP: "#ef4444", OTHER: "#475569" };
const SEV_COLORS = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#06b6d4", LOW: "#22c55e" };
const THREAT_COLORS = { PORT_SCAN_DETECTED: "#f97316", DNS_TUNNELING: "#ef4444", ICMP_TUNNELING: "#f97316", C2_BEACONING: "#ef4444", ARP_SPOOFING: "#f97316", COVERT_CHANNEL: "#eab308", NETWORK_RECONNAISSANCE: "#eab308", SUSPICIOUS_PORT: "#f97316", MALICIOUS_IP: "#ef4444" };
const MITRE = { PORT_SCAN_DETECTED: "T1046", DNS_TUNNELING: "T1071.004", ICMP_TUNNELING: "T1095", C2_BEACONING: "T1071", ARP_SPOOFING: "T1557", COVERT_CHANNEL: "T1572", NETWORK_RECONNAISSANCE: "T1595" };
const now = Date.now();
function rnd(b, v) { return Math.min(100, Math.max(0, b + (Math.random() - .5) * v)); }
const genHist = (n = 40) => Array.from({ length: n }, (_, i) => ({ time: new Date(Date.now() - (n - i) * 5000).toLocaleTimeString(), cpu: Math.round(rnd(35, 40)), ram: Math.round(rnd(55, 20)), disk: Math.round(rnd(62, 8)), net: Math.round(rnd(30, 50)) }));
const fmtTime = d => new Date(d).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const fmtDate = d => new Date(d).toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
const fmtFull = d => fmtDate(d) + " at " + fmtTime(d);
const timeAgo = d => { const m = Math.floor((Date.now() - new Date(d)) / 60000); return m < 1 ? "just now" : m < 60 ? m + "m ago" : m < 1440 ? Math.floor(m / 60) + "h ago" : Math.floor(m / 1440) + "d ago"; };
const fmtBytes = b => b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : b > 1024 ? `${(b / 1024).toFixed(1)} KB` : `${b} B`;

const THREATS = [
    { id: "t001", type: "CRYPTOMINER", icon: "⛏️", col: "#f97316", sev: "HIGH", conf: 92, ts: new Date(now - 3 * 60000), status: "ACTIVE", desc: 'Unknown process "cryptominer64.exe" consuming 91% CPU from C:\\Users\\AppData\\Local\\Temp.', msg: "Your PC is being secretly used to mine cryptocurrency for someone else.", steps: ["Process suspended automatically by SENTINEL", "Remove cryptominer64.exe from AppData\\Temp", "Check recently installed software (last 48h)", "Scan all browser extensions", "Change account passwords"] },
    { id: "t002", type: "SUSPICIOUS NETWORK", icon: "🌐", col: "#eab308", sev: "MEDIUM", conf: 74, ts: new Date(now - 12 * 60000), status: "ACTIVE", desc: "4 outbound connections to unrecognized IPs (185.220.x.x) on ports 4444 and 6666 — known C2 ports.", msg: "Your PC is communicating with potentially malicious command & control servers.", steps: ["Block IPs 185.220.101.x in Windows Firewall", "Identify source application via Task Manager", "Run Malwarebytes full system scan", "Temporarily disable internet if threat persists"] },
    { id: "t003", type: "ANOMALY DETECTED", icon: "🔍", col: "#3b82f6", sev: "MEDIUM", conf: 68, ts: new Date(now - 60 * 60000), status: "ACTIVE", desc: "ML model flagged behavior 3.2σ from 30-day baseline at 03:14 AM with no user session.", msg: "Your PC is behaving very differently from its normal pattern — possibly unauthorized remote activity.", steps: ["Review all processes started after midnight", "Check Event Viewer Security logs", "Monitor for 30 more minutes", "Run full antivirus scan if anomaly continues"] },
    { id: "t004", type: "BRUTE FORCE", icon: "🔨", col: "#f97316", sev: "HIGH", conf: 88, ts: new Date(now - 24 * 3600000), status: "RESOLVED", desc: "47 consecutive failed login attempts from local terminal within 3 minutes.", msg: "Something attempted to guess your account password repeatedly. Account was locked.", steps: ["Account lockout policy triggered", "Change your Windows account password", "Enable Windows Hello biometric or PIN", "Review other accounts sharing this password"] },
    { id: "t005", type: "RANSOMWARE", icon: "🔒", col: "#ef4444", sev: "CRITICAL", conf: 97, ts: new Date(now - 2 * 24 * 3600000), status: "RESOLVED", desc: 'Mass file renaming — 234 files modified with ".locked" extension in 8 seconds. Halted.', msg: "CRITICAL: Ransomware was detected and immediately stopped.", steps: ["Process suspended within 400ms", "Backup all files NOW to external drive", "Run FULL offline antivirus scan", "Do NOT pay any ransom", "Restore encrypted files from backup"] },
];
const PROCS = [
    { pid: 1234, name: "chrome.exe", cpu: 12.3, mem: 8.1, risk: 5, known: true, path: "C:\\Program Files\\Google\\Chrome" },
    { pid: 5678, name: "python.exe", cpu: 3.1, mem: 2.4, risk: 10, known: true, path: "C:\\Python313" },
    { pid: 9012, name: "svchost.exe", cpu: 1.2, mem: 1.8, risk: 5, known: true, path: "C:\\Windows\\System32" },
    { pid: 3456, name: "unknown_proc.exe", cpu: 45.6, mem: 12.3, risk: 88, known: false, path: "C:\\Users\\AppData\\Local\\Temp" },
    { pid: 7890, name: "node.exe", cpu: 5.4, mem: 4.2, risk: 10, known: true, path: "C:\\Program Files\\nodejs" },
    { pid: 2345, name: "explorer.exe", cpu: 0.8, mem: 1.1, risk: 5, known: true, path: "C:\\Windows" },
    { pid: 6543, name: "cryptominer64.exe", cpu: 91.2, mem: 18.4, risk: 97, known: false, path: "C:\\Users\\AppData\\Local\\Temp" },
    { pid: 8901, name: "code.exe", cpu: 8.2, mem: 15.3, risk: 5, known: true, path: "C:\\VSCode" },
];
const WEEKLY = [{ d: "Mon", c: 2, n: 1, a: 3, r: 0 }, { d: "Tue", c: 1, n: 3, a: 2, r: 0 }, { d: "Wed", c: 4, n: 2, a: 5, r: 1 }, { d: "Thu", c: 2, n: 4, a: 3, r: 0 }, { d: "Fri", c: 3, n: 1, a: 4, r: 0 }, { d: "Sat", c: 1, n: 2, a: 2, r: 0 }, { d: "Sun", c: 2, n: 3, a: 6, r: 0 }];
const PIE_D = [{ name: "Cryptominer", v: 35, c: "#f97316" }, { name: "Network", v: 25, c: "#eab308" }, { name: "Anomaly", v: 28, c: "#3b82f6" }, { name: "Ransomware", v: 12, c: "#ef4444" }];
const SEV_D = [{ name: "Critical", v: 40, c: "#ef4444" }, { name: "High", v: 40, c: "#f97316" }, { name: "Medium", v: 20, c: "#06b6d4" }, { name: "Low", v: 0, c: "#22c55e" }];
const PROTO_D = [{ name: "TCP", v: 8500, c: "#3b82f6" }, { name: "UDP", v: 4200, c: "#8b5cf6" }, { name: "DNS", v: 2720, c: "#22d3ee" }, { name: "HTTPS", v: 4100, c: "#22c55e" }, { name: "ICMP", v: 300, c: "#f97316" }, { name: "HTTP", v: 600, c: "#eab308" }];
const THREAT_DIST = [{ name: "Port Scan", v: 8, c: "#f97316" }, { name: "DNS Tunnel", v: 4, c: "#ef4444" }, { name: "C2 Beacon", v: 6, c: "#ef4444" }, { name: "Susp Port", v: 5, c: "#eab308" }];

const genPackets = (n = 120) => {
    const protos = ["TCP", "UDP", "DNS", "ICMP", "HTTPS", "HTTP"], wt = [35, 18, 18, 5, 18, 6];
    const local = ["192.168.1.10", "192.168.1.50", "10.0.0.5"], remote = ["8.8.8.8", "1.1.1.1", "185.220.101.45", "172.217.14.206", "52.96.1.1"];
    const spPorts = [4444, 6666, 1337, 31337], tTypes = ["PORT_SCAN_DETECTED", "DNS_TUNNELING", "C2_BEACONING", "SUSPICIOUS_PORT", "MALICIOUS_IP"];
    return Array.from({ length: n }, () => {
        let acc = 0, total = wt.reduce((a, b) => a + b, 0), r = Math.random() * total, proto = "TCP";
        for (let j = 0; j < protos.length; j++) { acc += wt[j]; if (r < acc) { proto = protos[j]; break; } }
        const susp = Math.random() < 0.1;
        return { timestamp: new Date(Date.now() - Math.random() * 300000).toISOString(), protocol: proto, src_ip: local[Math.floor(Math.random() * local.length)], dst_ip: remote[Math.floor(Math.random() * remote.length)], src_port: Math.floor(Math.random() * 16383) + 49152, dst_port: susp ? spPorts[Math.floor(Math.random() * spPorts.length)] : [80, 443, 53, 22, 8080][Math.floor(Math.random() * 5)], length: Math.floor(Math.random() * 1460) + 40, flags: ["SYN", "ACK", "SYN-ACK", "PSH-ACK", ""][Math.floor(Math.random() * 5)], is_suspicious: susp, threat_type: susp ? tTypes[Math.floor(Math.random() * tTypes.length)] : null, confidence: susp ? Math.floor(Math.random() * 25) + 70 : 0 };
    }).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};

const TT = ({ active, payload, label }) => { if (!active || !payload?.length) return null; return (<div style={{ background: "#060e18", border: "1px solid #0e1d33", borderRadius: 8, padding: "8px 12px", fontSize: 10, fontFamily: "'JetBrains Mono',monospace" }}><p style={{ color: "#475569", marginBottom: 4 }}>{label}</p>{payload.map((p, i) => <p key={i} style={{ color: p.color || p.fill }}>{p.name}: <b style={{ color: "#e2e8f0" }}>{typeof p.value === "number" ? p.value.toFixed(p.value < 10 ? 1 : 0) : p.value}</b></p>)}</div>); };
function Pulse({ color, size = 8 }) { return (<span style={{ position: "relative", display: "inline-flex", alignItems: "center", justifyContent: "center", width: size, height: size }}><span style={{ position: "absolute", inset: 0, borderRadius: "50%", background: color, opacity: .6, animation: "ping 1.6s cubic-bezier(0,0,.2,1) infinite" }} /><span style={{ width: size * .58, height: size * .58, borderRadius: "50%", background: color, display: "block", position: "relative" }} /></span>); }
function Pill({ children, color }) { return <span style={{ fontSize: 7, padding: "3px 9px", borderRadius: 999, fontWeight: 700, letterSpacing: 1.5, background: `${color}12`, color, border: `1px solid ${color}25` }}>{children}</span>; }
function FB({ active, color = "#3b82f6", onClick, children }) { return (<button onClick={onClick} style={{ padding: "4px 12px", borderRadius: 999, fontSize: 7, fontWeight: 700, cursor: "pointer", letterSpacing: 1.5, background: active ? `${color}10` : "rgba(255,255,255,.02)", border: active ? `1px solid ${color}30` : "1px solid #0e1d33", color: active ? color : "#253d5e", fontFamily: "'JetBrains Mono',monospace", transition: "all .2s" }}>{children}</button>); }

function Card({ children, style = {}, color, glow = false }) {
    const [hov, setHov] = useState(false);
    return (<div style={{ background: "linear-gradient(150deg,#0a1020,#07101c)", border: `1px solid ${hov && color ? color + "35" : color ? color + "18" : "#0e1d33"}`, borderRadius: 18, padding: 18, position: "relative", overflow: "hidden", transition: "border-color .25s,transform .2s", transform: hov ? "translateY(-1px)" : "translateY(0)", animation: glow ? "borderPulse 3s infinite" : "none", ...style }} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}>{children}</div>);
}

function MG({ label, value, icon, color, sub }) {
    const v = Math.min(100, Math.max(0, value || 0)), c = v > 85 ? "#ef4444" : v > 65 ? "#f97316" : color;
    return (<Card color={c}><div style={{ position: "absolute", top: -18, right: -18, width: 70, height: 70, borderRadius: "50%", background: `radial-gradient(circle,${c}08,transparent)` }} /><div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 12 }}><span style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3 }}>{label}</span><div style={{ width: 28, height: 28, borderRadius: 8, background: `${c}10`, border: `1px solid ${c}18`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13 }}>{icon}</div></div><div style={{ fontSize: 30, fontWeight: 900, color: c, fontFamily: "'Syne',sans-serif", lineHeight: 1 }}>{v.toFixed(0)}%</div><div style={{ height: 2, background: "#060e18", borderRadius: 999, overflow: "hidden", marginTop: 9 }}><div style={{ height: "100%", width: `${v}%`, background: `linear-gradient(90deg,${c}55,${c})`, borderRadius: 999, transition: "width .9s cubic-bezier(.4,0,.2,1)" }} /></div><div style={{ fontSize: 7, color: "#0d1e33", marginTop: 5 }}>{sub}</div></Card>);
}

function SC({ icon, label, value, color }) { return (<Card color={color} style={{ display: "flex", alignItems: "center", gap: 12, padding: "15px 16px" }}><div style={{ width: 37, height: 37, borderRadius: 11, background: `${color}10`, border: `1px solid ${color}18`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 17, flexShrink: 0 }}>{icon}</div><div><div style={{ fontSize: 24, fontWeight: 900, color, fontFamily: "'Syne',sans-serif", lineHeight: 1 }}>{value}</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 1.5, marginTop: 3 }}>{label}</div></div></Card>); }

function ThreatRow({ t, onResolve, expanded, onExpand }) {
    const c = SEV_COLORS[t.sev] || "#eab308";
    return (<><tr style={{ borderBottom: "1px solid #060e18", cursor: "pointer", transition: "background .12s" }} onMouseEnter={e => e.currentTarget.style.background = "rgba(30,58,95,.1)"} onMouseLeave={e => e.currentTarget.style.background = "transparent"} onClick={() => onExpand(t.id)}>
        <td style={{ padding: "12px 16px" }}><div style={{ display: "flex", alignItems: "center", gap: 8 }}><Pulse color={t.status === "ACTIVE" ? c : "#1a3050"} size={7} /><span style={{ fontSize: 15 }}>{t.icon}</span><span style={{ color: "#c8d8f0", fontSize: 10, fontWeight: 700 }}>{t.type}</span></div></td>
        <td style={{ padding: "12px 14px" }}><Pill color={c}>{t.sev}</Pill></td>
        <td style={{ padding: "12px 14px" }}><div style={{ display: "flex", alignItems: "center", gap: 7 }}><div style={{ width: 50, height: 2, background: "#060e18", borderRadius: 999, overflow: "hidden" }}><div style={{ height: "100%", width: `${t.conf}%`, background: `linear-gradient(90deg,${c}50,${c})`, borderRadius: 999 }} /></div><span style={{ fontSize: 9, fontWeight: 700, color: c }}>{t.conf}%</span></div></td>
        <td style={{ padding: "12px 14px" }}><div><div style={{ fontSize: 10, fontWeight: 700, color: "#c8d8f0", fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(t.ts)}</div><div style={{ fontSize: 8, color: "#253d5e", marginTop: 1 }}>{timeAgo(t.ts)}</div></div></td>
        <td style={{ padding: "12px 14px" }}><span style={{ fontSize: 9, color: "#1a3050", fontFamily: "'JetBrains Mono',monospace" }}>{fmtDate(t.ts)}</span></td>
        <td style={{ padding: "12px 14px" }}><Pill color={t.status === "ACTIVE" ? "#ef4444" : "#22c55e"}>{t.status}</Pill></td>
        <td style={{ padding: "12px 8px", color: "#1a3050", fontSize: 10 }}>{expanded ? "▲" : "▼"}</td>
    </tr>
        {expanded && <tr style={{ background: "#030810" }}><td colSpan={7} style={{ padding: "0 16px 16px" }}>
            <div style={{ background: "#060e18", border: "1px solid #0e1d33", borderRadius: 13, padding: 18, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 18 }}>
                <div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 8 }}>INCIDENT DETAILS</div><p style={{ color: "#94a3b8", fontSize: 10, lineHeight: 1.7 }}>{t.desc}</p><div style={{ marginTop: 10, padding: "10px 12px", background: "#030810", borderRadius: "0 8px 8px 0", borderLeft: `2px solid ${c}` }}><p style={{ color: "#c8d8f0", fontSize: 10, lineHeight: 1.6 }}>{t.msg}</p></div><div style={{ marginTop: 12, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}><div style={{ background: "#030810", border: "1px solid #0e1d33", borderRadius: 8, padding: "8px 10px" }}><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginBottom: 4 }}>DETECTED AT</div><div style={{ fontSize: 10, fontWeight: 700, color: "#c8d8f0", fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(t.ts)}</div><div style={{ fontSize: 8, color: "#253d5e", marginTop: 1 }}>{fmtDate(t.ts)}</div></div><div style={{ background: "#030810", border: "1px solid #0e1d33", borderRadius: 8, padding: "8px 10px" }}><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginBottom: 4 }}>FULL TIMESTAMP</div><div style={{ fontSize: 9, fontWeight: 700, color: c, fontFamily: "'JetBrains Mono',monospace" }}>{fmtFull(t.ts)}</div></div></div></div>
                <div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 8 }}>RESPONSE ACTIONS ({t.steps.length} STEPS)</div>{t.steps.map((s, i) => <div key={i} style={{ display: "flex", gap: 8, alignItems: "flex-start", marginBottom: 7 }}><span style={{ minWidth: 17, height: 17, borderRadius: 5, background: `${c}12`, color: c, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 7, fontWeight: 900, border: `1px solid ${c}20`, flexShrink: 0 }}>{i + 1}</span><span style={{ color: "#94a3b8", fontSize: 9, lineHeight: 1.55 }}>{s}</span></div>)}{t.status === "ACTIVE" ? <button onClick={e => { e.stopPropagation(); onResolve(t.id); }} style={{ marginTop: 10, padding: "8px 0", width: "100%", borderRadius: 8, background: "rgba(34,197,94,.07)", border: "1px solid rgba(34,197,94,.18)", color: "#22c55e", fontSize: 8, fontWeight: 700, cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", letterSpacing: 2 }}>✓ MARK AS RESOLVED</button> : <div style={{ marginTop: 10, padding: "8px 0", borderRadius: 8, background: "rgba(34,197,94,.04)", border: "1px solid rgba(34,197,94,.1)", color: "#22c55e", fontSize: 8, textAlign: "center", letterSpacing: 2 }}>✓ RESOLVED</div>}</div>
            </div>
        </td></tr>}</>);
}

function ProcRow({ p }) {
    const rc = p.risk > 70 ? "#ef4444" : p.risk > 40 ? "#f97316" : "#22c55e";
    return (<tr style={{ borderBottom: "1px solid #060e18", transition: "background .12s" }} onMouseEnter={e => e.currentTarget.style.background = "rgba(30,58,95,.08)"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}><td style={{ padding: "10px 14px" }}><div style={{ display: "flex", alignItems: "center", gap: 7 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: rc, flexShrink: 0 }} /><span style={{ color: "#c8d8f0", fontSize: 10 }}>{p.name}</span>{!p.known && <Pill color="#f97316">UNKNOWN</Pill>}</div><div style={{ fontSize: 7, color: "#0d1e33", marginTop: 2, marginLeft: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.path}</div></td><td style={{ padding: "10px 14px", textAlign: "right", fontSize: 9, color: "#1a3050" }}>{p.pid}</td><td style={{ padding: "10px 14px", textAlign: "right" }}><span style={{ fontSize: 10, fontWeight: 700, color: p.cpu > 60 ? "#ef4444" : p.cpu > 30 ? "#f97316" : "#475569" }}>{p.cpu.toFixed(1)}%</span></td><td style={{ padding: "10px 14px", textAlign: "right", fontSize: 10, color: "#475569" }}>{p.mem.toFixed(1)}%</td><td style={{ padding: "10px 14px", textAlign: "right" }}><div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 7 }}><div style={{ width: 44, height: 2, background: "#060e18", borderRadius: 999, overflow: "hidden" }}><div style={{ height: "100%", width: `${p.risk}%`, background: `linear-gradient(90deg,${rc}50,${rc})`, borderRadius: 999 }} /></div><span style={{ fontSize: 9, fontWeight: 700, color: rc, minWidth: 18, textAlign: "right" }}>{p.risk}</span></div></td></tr>);
}

function PacketRow({ pkt }) {
    const pc = PROTO_COLORS[pkt.protocol] || PROTO_COLORS.OTHER, tc = pkt.threat_type ? (THREAT_COLORS[pkt.threat_type] || "#eab308") : null;
    return (<tr style={{ borderBottom: "1px solid #060e18", transition: "background .12s" }} onMouseEnter={e => e.currentTarget.style.background = "rgba(30,58,95,.1)"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}><td style={{ padding: "8px 14px", fontSize: 9, color: "#253d5e", fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(pkt.timestamp)}</td><td style={{ padding: "8px 14px" }}><Pill color={pc}>{pkt.protocol}</Pill></td><td style={{ padding: "8px 14px", fontSize: 9, color: "#475569", fontFamily: "'JetBrains Mono',monospace" }}>{pkt.src_ip}:{pkt.src_port}</td><td style={{ padding: "8px 14px", fontSize: 9, color: "#475569", fontFamily: "'JetBrains Mono',monospace" }}>{pkt.dst_ip}:{pkt.dst_port}</td><td style={{ padding: "8px 14px", fontSize: 9, color: "#334155", textAlign: "right", fontFamily: "'JetBrains Mono',monospace" }}>{fmtBytes(pkt.length)}</td><td style={{ padding: "8px 14px", fontSize: 8, color: "#253d5e" }}>{pkt.flags || "—"}</td><td style={{ padding: "8px 14px" }}>{pkt.is_suspicious ? (<div><Pill color={tc || "#eab308"}>{(pkt.threat_type || "").replace(/_/g, " ")}</Pill>{MITRE[pkt.threat_type] && <div style={{ fontSize: 7, color: "#1a3050", marginTop: 2 }}>MITRE {MITRE[pkt.threat_type]}</div>}</div>) : <span style={{ fontSize: 7, color: "#0d1e33" }}>CLEAN</span>}</td><td style={{ padding: "8px 14px", textAlign: "right" }}>{pkt.is_suspicious && pkt.confidence > 0 && <span style={{ fontSize: 9, fontWeight: 700, color: tc || "#eab308" }}>{pkt.confidence}%</span>}</td></tr>);
}

// Helper to get threat icon based on type
function getThreatIcon(type) {
    const icons = {
        CRYPTOMINER: "⛏️", MALWARE: "🦠", RANSOMWARE: "🔒", SPYWARE: "👁️",
        BRUTE_FORCE: "🔨", NETWORK: "🌐", ANOMALY: "🔍", PORT_SCAN: "📡",
        DNS_TUNNEL: "🔮", C2_BEACON: "📶", SUSPICIOUS: "⚠️"
    };
    for (const [key, icon] of Object.entries(icons)) {
        if (type.toUpperCase().includes(key)) return icon;
    }
    return "🚨";
}

export default function App() {
    const [tab, setTab] = useState("overview");
    const [history, setHistory] = useState(genHist);
    const [threats, setThreats] = useState([]);
    const [packets, setPackets] = useState([]);
    const [processes, setProcs] = useState([]);
    const [expanded, setExpand] = useState(null);
    const [tFilter, setTF] = useState("ALL");
    const [pFilter, setPF] = useState("ALL");
    const [pProto, setPP] = useState("ALL");
    const [search, setSrch] = useState("");
    const [cpu, setCpu] = useState(0);
    const [ram, setRam] = useState(0);
    const [disk, setDisk] = useState(0);
    const [net, setNet] = useState(0);
    const [activeConns, setActiveConns] = useState(0);
    const [connected, setConn] = useState(false);
    const [loading, setLoading] = useState(true);
    const [time, setTime] = useState(new Date().toLocaleTimeString());
    const [exportMsg, setExportMsg] = useState("");
    const [anomalyScore, setAnomalyScore] = useState(0);
    const [threatStats, setThreatStats] = useState({ total: 0, resolved: 0, avgConfidence: 0, critical: 0 });
    const [protoStats, setProtoStats] = useState([]);
    const [threatTypeStats, setThreatTypeStats] = useState([]);
    const [severityStats, setSeverityStats] = useState([]);
    const [metricsData, setMetricsData] = useState(null);

    useEffect(() => { const id = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000); return () => clearInterval(id); }, []);

    // Fetch ALL real-time data from backend
    useEffect(() => {
        const fetchAllData = async () => {
            const t = new Date().toLocaleTimeString();
            try {
                // Fetch metrics
                const metricsRes = await fetch(`${API}/metrics/live`);
                if (!metricsRes.ok) throw new Error();
                const metricsData = await metricsRes.json();
                setMetricsData(metricsData);

                // Fetch threats
                const threatsRes = await fetch(`${API}/threats`);
                const threatsData = threatsRes.ok ? await threatsRes.json() : { threats: [] };

                // Fetch suspicious packets
                const packetsRes = await fetch(`${API}/packets/suspicious?limit=50`);
                const packetsData = packetsRes.ok ? await packetsRes.json() : { packets: [] };

                // Fetch processes
                const procsRes = await fetch(`${API}/processes`);
                const procsData = procsRes.ok ? await procsRes.json() : { processes: [] };

                // Update state with REAL data
                setCpu(Math.round(metricsData.system.cpu_percent));
                setRam(Math.round(metricsData.system.ram_percent));
                setDisk(Math.round(metricsData.system.disk_percent));
                setNet(Math.round((metricsData.network.bytes_sent + metricsData.network.bytes_recv) / 1048576)); // Convert to MB
                setActiveConns(metricsData.network.active_connections || 0);
                setAnomalyScore(metricsData.detection?.anomaly_score || 0);
                setConn(true);
                setLoading(false);

                setHistory(p => [...p, {
                    time: t,
                    cpu: Math.round(metricsData.system.cpu_percent),
                    ram: Math.round(metricsData.system.ram_percent),
                    disk: Math.round(metricsData.system.disk_percent),
                    net: Math.round((metricsData.network.bytes_sent + metricsData.network.bytes_recv) / 1048576)
                }].slice(-40));

                // Transform backend threats to frontend format
                const formattedThreats = (threatsData.threats || []).map(t => ({
                    ...t,
                    id: t.id || t._id || `t_${Date.now()}_${Math.random()}`,
                    icon: getThreatIcon(t.type),
                    col: THREAT_COLORS[t.type] || SEV_COLORS[t.severity] || "#eab308",
                    sev: t.severity || "MEDIUM",
                    conf: t.confidence || 75,
                    ts: t.detected_at ? new Date(t.detected_at) : new Date(),
                    status: t.status || "ACTIVE",
                    desc: t.description || t.user_message || "Threat detected",
                    msg: t.user_message || t.description || "Security threat detected",
                    steps: t.preventive_steps || ["Review threat details", "Take appropriate action"]
                }));
                setThreats(formattedThreats);

                // Transform backend packets
                const formattedPackets = (packetsData.packets || []).map(p => ({
                    ...p,
                    timestamp: p.timestamp || new Date().toISOString(),
                    protocol: p.protocol || "TCP",
                    src_ip: p.src_ip || "0.0.0.0",
                    dst_ip: p.dst_ip || "0.0.0.0",
                    src_port: p.src_port || 0,
                    dst_port: p.dst_port || 0,
                    length: p.length || 0,
                    flags: p.flags || "",
                    is_suspicious: p.is_suspicious || false,
                    threat_type: p.threat_type || null,
                    confidence: p.confidence || 0
                }));
                setPackets(formattedPackets);

                // Transform backend processes
                const formattedProcs = (procsData.processes || []).map(p => ({
                    ...p,
                    pid: p.pid || 0,
                    name: p.name || "unknown",
                    cpu: p.cpu_percent || 0,
                    mem: p.memory_percent || 0,
                    risk: p.risk_score || 0,
                    known: p.is_known !== false,
                    path: p.exe_path || "Unknown"
                }));
                setProcs(formattedProcs);

                // Calculate real-time statistics from threats data
                const totalThreats = formattedThreats.length;
                const resolvedThreats = formattedThreats.filter(t => t.status === "RESOLVED").length;
                const avgConf = totalThreats > 0 ? Math.round(formattedThreats.reduce((sum, t) => sum + (t.conf || 0), 0) / totalThreats) : 0;
                const criticalCount = formattedThreats.filter(t => t.sev === "CRITICAL").length;
                setThreatStats({ total: totalThreats, resolved: resolvedThreats, avgConfidence: avgConf, critical: criticalCount });

                // Calculate protocol distribution from packets
                const protoCounts = {};
                formattedPackets.forEach(p => {
                    const proto = p.protocol || "OTHER";
                    protoCounts[proto] = (protoCounts[proto] || 0) + 1;
                });
                const totalPkts = formattedPackets.length;
                setProtoStats(Object.entries(protoCounts).map(([name, v]) => ({
                    name,
                    v: Math.round((v / totalPkts) * 100) || 0,
                    c: PROTO_COLORS[name] || "#475569"
                })));

                // Calculate threat type distribution
                const typeCounts = {};
                formattedThreats.forEach(t => {
                    const type = t.type || "UNKNOWN";
                    typeCounts[type] = (typeCounts[type] || 0) + 1;
                });
                setThreatTypeStats(Object.entries(typeCounts).map(([name, v]) => ({
                    name,
                    v: Math.round((v / totalThreats) * 100) || 0,
                    c: THREAT_COLORS[name] || SEV_COLORS["MEDIUM"] || "#eab308"
                })));

                // Calculate severity distribution
                const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
                formattedThreats.forEach(t => {
                    const sev = t.sev || "MEDIUM";
                    sevCounts[sev] = (sevCounts[sev] || 0) + 1;
                });
                setSeverityStats(Object.entries(sevCounts).map(([name, v]) => ({
                    name,
                    v: totalThreats > 0 ? Math.round((v / totalThreats) * 100) : 0,
                    c: SEV_COLORS[name] || "#22c55e"
                })));

                console.log("✅ Backend connected - REAL data loaded");
                console.log(`  Threats: ${formattedThreats.length}, Packets: ${formattedPackets.length}, Processes: ${formattedProcs.length}`);
            }
            catch (e) {
                console.log("❌ Backend not available - using DEMO data");
                setConn(false);
                setLoading(false);
                // Fallback to demo data only if arrays are empty
                setThreats(prev => prev.length === 0 ? THREATS : prev);
                setPackets(prev => prev.length === 0 ? genPackets(120) : prev);
                setProcs(prev => prev.length === 0 ? PROCS : prev);
                const nc = Math.round(rnd(cpu, 18)), nr = Math.round(rnd(ram, 10)), nd = Math.round(rnd(disk, 4));
                setCpu(nc); setRam(nr); setDisk(nd);
                setHistory(p => [...p, { time: t, cpu: nc, ram: nr, disk: nd, net: Math.round(rnd(30, 50)) }].slice(-40));
            }
        };

        fetchAllData();
        const id = setInterval(fetchAllData, 5000); // Refresh every 5 seconds
        return () => clearInterval(id);
    }, []);

    const active = threats.filter(t => t.status === "ACTIVE");
    const resolve = async (id) => {
        // Call backend API to resolve threat
        try {
            await fetch(`${API}/threats/${id}/resolve`, { method: 'POST' });
            // Update local state optimistically
            setThreats(p => p.map(t => t.id === id ? { ...t, status: "RESOLVED" } : t));
        } catch (e) {
            console.error("Failed to resolve threat:", e);
        }
    };
    const toggleExp = id => setExpand(p => p === id ? null : id);
    const health = Math.max(0, 100 - active.length * 15 - (cpu > 80 ? 15 : 0));
    const hc = health > 70 ? "#22c55e" : health > 40 ? "#f97316" : "#ef4444";
    const filteredT = threats.filter(t => { const mf = tFilter === "ALL" || t.status === tFilter || t.sev === tFilter; const ms = t.type.toLowerCase().includes(search.toLowerCase()) || t.desc.toLowerCase().includes(search.toLowerCase()); return mf && ms; });
    const filteredP = packets.filter(p => { const mf = pFilter === "ALL" || (pFilter === "SUSPICIOUS" ? p.is_suspicious : !p.is_suspicious); const mp = pProto === "ALL" || p.protocol === pProto; return mf && mp; });
    const suspPkts = packets.filter(p => p.is_suspicious);

    const handleExport = async () => { setExportMsg("Capturing..."); try { const r = await fetch(`${API}/packets/export`, { method: "POST" }); const d = await r.json(); setExportMsg("✅ " + d.file); } catch { setExportMsg("⚠️ Demo mode — export unavailable"); } setTimeout(() => setExportMsg(""), 4000); };

    const TABS = [{ id: "overview", label: "OVERVIEW" }, { id: "threats", label: "THREATS", badge: active.length }, { id: "analytics", label: "ANALYTICS" }, { id: "packets", label: "PACKETS", badge: suspPkts.length || 0 }, { id: "processes", label: "PROCESSES" }, { id: "network", label: "NETWORK" }, { id: "timeline", label: "TIMELINE" }];

    const S = { card: { background: "linear-gradient(150deg,#0a1020,#07101c)", border: "1px solid #0e1d33", borderRadius: 18, padding: 18 }, thead: { borderBottom: "1px solid #060e18", background: "#04080f" }, th: { padding: "11px 14px", fontSize: 7, color: "#1a3050", letterSpacing: 2, textAlign: "left", fontWeight: 700 } };

    return (<div style={{ minHeight: "100vh", background: "#030810", color: "#e2e8f0", fontFamily: "'JetBrains Mono',monospace", display: "flex", flexDirection: "column" }}>
        <style>{`@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700;900&family=Syne:wght@700;800;900&display=swap');*{box-sizing:border-box;margin:0;padding:0;}body{background:#030810;}@keyframes ping{0%{transform:scale(1);opacity:.9}100%{transform:scale(2.5);opacity:0}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}@keyframes borderPulse{0%,100%{border-color:rgba(239,68,68,.12)}50%{border-color:rgba(239,68,68,.45)}}@keyframes ticker{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}::-webkit-scrollbar{width:2px;height:2px;}::-webkit-scrollbar-thumb{background:#1a2f50;}::-webkit-scrollbar-track{background:#030810;}`}</style>

        {/* TICKER */}
        <div style={{ overflow: "hidden", background: "#04090f", borderBottom: "1px solid #080f1c", padding: "5px 0", whiteSpace: "nowrap" }}>
            <span style={{ display: "inline-block", animation: "ticker 45s linear infinite", fontSize: 8, color: "#1a3050", letterSpacing: 2, padding: "0 30px" }}>◈ SENTINEL v3.0 ACTIVE &nbsp;·&nbsp; {processes.length || PROCS.length} PROCESSES &nbsp;·&nbsp; {packets.length} PACKETS CAPTURED &nbsp;·&nbsp; {suspPkts.length} SUSPICIOUS &nbsp;·&nbsp; {active.length} ACTIVE THREATS &nbsp;·&nbsp; CPU: {cpu}% &nbsp;·&nbsp; RAM: {ram}% &nbsp;·&nbsp; {time} &nbsp;·&nbsp; PACKET INSPECTOR ACTIVE &nbsp;·&nbsp; ML BASELINE: {(anomalyScore * 100).toFixed(0)}% &nbsp;·&nbsp; ◈ SENTINEL v3.0 ACTIVE &nbsp;·&nbsp; {processes.length || PROCS.length} PROCESSES &nbsp;·&nbsp; {packets.length} PACKETS CAPTURED &nbsp;·&nbsp;</span>
        </div>

        {/* HEADER */}
        <header style={{ background: "rgba(3,8,16,.98)", borderBottom: "1px solid #080f1c", padding: "0 20px", height: 54, display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, zIndex: 50 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
                <div style={{ width: 32, height: 32, borderRadius: 9, background: "#060e18", border: "1px solid #0e1d33", display: "flex", alignItems: "center", justifyContent: "center" }}><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinecap="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg></div>
                <div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 13, fontWeight: 900, letterSpacing: 6, color: "#c8d8f0" }}>SENTINEL</div><div style={{ fontSize: 7, color: "#0d1e33", letterSpacing: 4, marginTop: 1 }}>AI ENDPOINT SECURITY · v3.0</div></div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "5px 12px", background: "#060e18", border: "1px solid #0e1d33", borderRadius: 9 }}><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={hc} strokeWidth="2.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg><span style={{ fontSize: 8, color: "#475569", letterSpacing: 1 }}>HEALTH</span><span style={{ fontSize: 12, fontWeight: 900, color: hc, fontFamily: "'Syne',sans-serif" }}>{health}%</span></div>
                <div style={{ display: "flex", alignItems: "center", gap: 7, padding: "5px 12px", background: "rgba(249,115,22,.07)", border: "1px solid rgba(249,115,22,.22)", borderRadius: 9 }}><Pulse color="#f97316" size={7} /><span style={{ fontSize: 9, fontWeight: 700, color: "#f97316", letterSpacing: 3 }}>WARNING</span></div>
                <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 11px", background: "#060e18", border: "1px solid #080f1c", borderRadius: 9 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: connected ? "#22c55e" : "#f97316", animation: "pulse 2s infinite" }} /><span style={{ fontSize: 10, color: "#1a3050", minWidth: 68 }}>{time}</span></div>
            </div>
        </header>

        <div style={{ display: "flex", flex: 1 }}>
            {/* SIDEBAR */}
            <aside style={{ width: 186, background: "#030810", borderRight: "1px solid #080f1c", display: "flex", flexDirection: "column", flexShrink: 0, position: "sticky", top: 0, height: "calc(100vh - 77px)", overflow: "hidden" }}>
                <div style={{ overflowY: "auto", flexShrink: 0, paddingTop: 14 }}>
                    {TABS.map(t => <button key={t.id} onClick={() => setTab(t.id)} style={{ display: "flex", alignItems: "center", gap: 9, padding: "10px 16px", background: tab === t.id ? "rgba(30,60,100,.2)" : "transparent", border: "none", borderLeft: tab === t.id ? "2px solid #3b82f6" : "2px solid transparent", color: tab === t.id ? "#60a5fa" : "#253d5e", cursor: "pointer", fontSize: 9, letterSpacing: 2.5, fontFamily: "'JetBrains Mono',monospace", transition: "all .2s", textAlign: "left", width: "100%" }}>
                        {t.label}{t.badge > 0 && <span style={{ marginLeft: "auto", background: "#ef4444", color: "#fff", borderRadius: 999, minWidth: 14, height: 14, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 7, fontWeight: 900 }}>{t.badge}</span>}
                    </button>)}
                </div>
                <div style={{ marginTop: "auto", padding: "0 12px 12px", display: "flex", flexDirection: "column", gap: 8 }}>
                    <div style={{ padding: 12, background: "#060e18", border: "1px solid #080f1c", borderRadius: 12 }}>
                        <div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 7 }}>ML ENGINE</div>
                        <div style={{ height: 2, background: "#080f1c", borderRadius: 999, overflow: "hidden", marginBottom: 5 }}><div style={{ height: "100%", width: `${Math.min(history.length / 40 * 100, 100)}%`, background: "linear-gradient(90deg,#1a3050,#3b82f6)", borderRadius: 999, transition: "width .5s" }} /></div>
                        <div style={{ display: "flex", justifyContent: "space-between" }}><span style={{ fontSize: 7, color: "#0d1e33" }}>BASELINE</span><span style={{ fontSize: 8, color: "#1a3050", fontWeight: 700 }}>{Math.min(history.length, 40)}/40</span></div>
                        <div style={{ marginTop: 10, fontSize: 7, color: "#1a3050", letterSpacing: 3 }}>ANOMALY SCORE</div>
                        <div style={{ fontSize: 22, fontWeight: 900, color: anomalyScore > 0.75 ? "#ef4444" : anomalyScore > 0.5 ? "#f97316" : anomalyScore > 0.3 ? "#06b6d4" : "#22c55e", fontFamily: "'Syne',sans-serif", marginTop: 4, lineHeight: 1 }}>{(anomalyScore * 100).toFixed(0)}%</div>
                        <div style={{ fontSize: 7, color: anomalyScore > 0.75 ? "#ef4444" : anomalyScore > 0.5 ? "#f97316" : anomalyScore > 0.3 ? "#06b6d4" : "#22c55e", marginTop: 2, letterSpacing: 2 }}>{anomalyScore > 0.75 ? "CRITICAL" : anomalyScore > 0.5 ? "HIGH RISK" : anomalyScore > 0.3 ? "ELEVATED" : "NORMAL RANGE"}</div>
                    </div>
                    <div style={{ padding: "10px 12px", background: "#060e18", border: "1px solid #080f1c", borderRadius: 12 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 3 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: connected ? "#22c55e" : "#f97316", animation: "pulse 2s infinite" }} /><span style={{ fontSize: 8, color: "#253d5e", letterSpacing: 1 }}>{connected ? "LIVE FEED" : "DEMO MODE"}</span></div>
                        <div style={{ fontSize: 7, color: "#0d1e33" }}>{connected ? "Backend connected" : "Run backend for live data"}</div>
                    </div>
                </div>
            </aside>

            {/* MAIN */}
            <main style={{ flex: 1, padding: 18, overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>

                {/* ── OVERVIEW ── */}
                {tab === "overview" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 13 }}>
                        <MG label="CPU USAGE" value={cpu} icon="🖥️" color="#3b82f6" sub={`${cpu}% of ${navigator.hardwareConcurrency || 4} cores`} />
                        <MG label="RAM USAGE" value={ram} icon="💾" color="#8b5cf6" sub={`${(ram / 100 * 16).toFixed(1)} GB / 16 GB`} />
                        <MG label="DISK USAGE" value={disk} icon="💿" color="#06b6d4" sub="C:\\ · 328 GB / 512 GB" />
                        <MG label="NETWORK" value={net > 100 ? 100 : net} icon="🌐" color="#22c55e" sub={`${activeConns} active connections · ${net} MB transferred`} />
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 13 }}>
                        <Card><div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}><span style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3 }}>REAL-TIME SYSTEM METRICS</span><div style={{ display: "flex", gap: 12 }}>{[["CPU", "#3b82f6"], ["RAM", "#8b5cf6"], ["NET", "#22c55e"]].map(([l, c]) => <span key={l} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 7, color: "#253d5e" }}><span style={{ width: 14, height: 2, background: c, display: "inline-block", borderRadius: 1 }} />{l}</span>)}</div></div><ResponsiveContainer width="100%" height={140}><AreaChart data={history} margin={{ top: 5, right: 5, bottom: 0, left: -22 }}><defs>{[["cpu", "#3b82f6"], ["ram", "#8b5cf6"], ["net", "#22c55e"]].map(([k, c]) => <linearGradient key={k} id={`g${k}`} x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={c} stopOpacity={.15} /><stop offset="95%" stopColor={c} stopOpacity={0} /></linearGradient>)}</defs><CartesianGrid strokeDasharray="3 3" stroke="#060e18" /><XAxis dataKey="time" tick={{ fill: "#1a3050", fontSize: 8 }} interval={7} /><YAxis domain={[0, 100]} tick={{ fill: "#1a3050", fontSize: 8 }} /><Tooltip content={<TT />} />{[["cpu", "#3b82f6"], ["ram", "#8b5cf6"], ["net", "#22c55e"]].map(([k, c]) => <Area key={k} type="monotone" dataKey={k} stroke={c} fill={`url(#g${k})`} strokeWidth={1.5} dot={false} name={k.toUpperCase()} />)}</AreaChart></ResponsiveContainer></Card>
                        <Card><span style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, display: "block", marginBottom: 12 }}>THREAT DISTRIBUTION</span><ResponsiveContainer width="100%" height={110}><PieChart><Pie data={PIE_D} cx="50%" cy="50%" innerRadius={32} outerRadius={52} paddingAngle={3} dataKey="v">{PIE_D.map((e, i) => <Cell key={i} fill={e.c} stroke="#0a1020" strokeWidth={2} />)}</Pie><Tooltip content={<TT />} /></PieChart></ResponsiveContainer><div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 9 }}>{PIE_D.map((e, i) => <div key={i} style={{ display: "flex", justifyContent: "space-between" }}><span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 8, color: "#253d5e" }}><span style={{ width: 6, height: 6, borderRadius: 2, background: e.c, display: "inline-block" }} />{e.name}</span><span style={{ fontSize: 8, fontWeight: 700, color: e.c }}>{e.v}%</span></div>)}</div></Card>
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 13 }}>
                        <SC icon="🚨" label="ACTIVE THREATS" value={active.length} color={active.length > 0 ? "#ef4444" : "#22c55e"} />
                        <SC icon="📦" label="PACKETS CAPTURED" value={packets.length} color="#3b82f6" />
                        <SC icon="⚠️" label="SUSPICIOUS PKTS" value={suspPkts.length} color="#f97316" />
                        <SC icon="🧠" label="TOTAL THREATS" value={threats.length} color="#8b5cf6" />
                    </div>
                    {active.length > 0 && <Card color="#ef4444" glow style={{ padding: 16 }}><div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 13 }}><div style={{ display: "flex", alignItems: "center", gap: 8 }}><Pulse color="#ef4444" size={8} /><span style={{ fontSize: 7, fontWeight: 700, color: "#ef4444", letterSpacing: 3 }}>ACTIVE THREATS</span></div><button onClick={() => setTab("threats")} style={{ padding: "4px 11px", borderRadius: 8, background: "rgba(59,130,246,.06)", border: "1px solid rgba(59,130,246,.16)", color: "#3b82f6", fontSize: 8, cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", letterSpacing: 1 }}>VIEW ALL →</button></div>{active.slice(0, 3).map(t => { const c = SEV_COLORS[t.sev] || "#eab308"; return (<div key={t.id} style={{ padding: "9px 0", borderBottom: "1px solid #060e18", display: "flex", justifyContent: "space-between", alignItems: "center" }}><div style={{ display: "flex", alignItems: "center", gap: 9, flex: 1, minWidth: 0 }}><span style={{ fontSize: 14, flexShrink: 0 }}>{t.icon}</span><div style={{ minWidth: 0 }}><div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}><span style={{ color: "#c8d8f0", fontSize: 10, fontWeight: 700 }}>{t.type}</span><Pill color={c}>{t.sev}</Pill></div><p style={{ color: "#253d5e", fontSize: 9, marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{t.desc.substring(0, 68)}...</p></div></div><div style={{ textAlign: "right", marginLeft: 10, flexShrink: 0 }}><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 1 }}>DETECTED</div><div style={{ fontSize: 10, fontWeight: 700, color: c, fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(t.ts)}</div><div style={{ fontSize: 8, color: "#1a3050" }}>{fmtDate(t.ts)}</div></div></div>); })}</Card>}
                    <Card><div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}><span style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3 }}>RECENT SUSPICIOUS PACKETS</span><button onClick={() => setTab("packets")} style={{ padding: "4px 11px", borderRadius: 8, background: "rgba(59,130,246,.06)", border: "1px solid rgba(59,130,246,.16)", color: "#3b82f6", fontSize: 8, cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", letterSpacing: 1 }}>INSPECT →</button></div>{suspPkts.slice(0, 4).map((p, i) => { const tc = THREAT_COLORS[p.threat_type] || "#eab308"; return (<div key={i} style={{ padding: "8px 0", borderBottom: "1px solid #060e18", display: "flex", justifyContent: "space-between", alignItems: "center" }}><div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 0 }}><Pill color={PROTO_COLORS[p.protocol] || "#3b82f6"}>{p.protocol}</Pill><span style={{ fontSize: 9, color: "#475569", fontFamily: "'JetBrains Mono',monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port}</span><Pill color={tc}>{(p.threat_type || "").replace(/_/g, " ")}</Pill>{MITRE[p.threat_type] && <span style={{ fontSize: 7, color: "#1a3050" }}>MITRE {MITRE[p.threat_type]}</span>}</div><span style={{ fontSize: 10, fontWeight: 700, color: tc, fontFamily: "'JetBrains Mono',monospace", flexShrink: 0, marginLeft: 8 }}>{fmtTime(p.timestamp)}</span></div>); })}</Card>
                </div>}

                {/* ── THREATS ── */}
                {tab === "threats" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}><div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>THREAT CENTER</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>{active.length} ACTIVE · {threats.filter(t => t.status === "RESOLVED").length} RESOLVED · {threats.length} TOTAL</div></div><div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>{["ALL", "ACTIVE", "RESOLVED", "CRITICAL", "HIGH", "MEDIUM"].map(f => <FB key={f} active={tFilter === f} onClick={() => setTF(f)}>{f}</FB>)}</div></div>
                    <div style={{ position: "relative" }}><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#1a3050" strokeWidth="2" style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", pointerEvents: "none" }}><circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" /></svg><input value={search} onChange={e => setSrch(e.target.value)} placeholder="Search threats..." style={{ width: "100%", padding: "10px 14px 10px 36px", background: "#060e18", border: "1px solid #0e1d33", borderRadius: 10, color: "#94a3b8", fontSize: 10, fontFamily: "'JetBrains Mono',monospace", outline: "none" }} /></div>
                    <Card style={{ padding: 0, overflow: "hidden" }}><table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr style={S.thead}>{["THREAT TYPE", "SEVERITY", "CONFIDENCE", "DETECTED AT", "DATE", "STATUS", ""].map(h => <th key={h} style={S.th}>{h}</th>)}</tr></thead><tbody>{filteredT.length === 0 ? <tr><td colSpan={7} style={{ textAlign: "center", padding: "50px 0", color: "#1a3050", fontSize: 8, letterSpacing: 3 }}>NO THREATS MATCH FILTER</td></tr> : filteredT.map(t => <ThreatRow key={t.id} t={t} onResolve={resolve} expanded={expanded === t.id} onExpand={toggleExp} />)}</tbody></table></Card>
                </div>}

                {/* ── ANALYTICS ── */}
                {tab === "analytics" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>THREAT ANALYTICS</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>7-DAY INTELLIGENCE OVERVIEW</div></div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 13 }}>{[{ l: "TOTAL DETECTED", v: threatStats.total, c: "#3b82f6" }, { l: "AUTO RESOLVED", v: threatStats.resolved, c: "#22c55e" }, { l: "AVG CONFIDENCE", v: threatStats.avgConfidence + "%", c: "#8b5cf6" }, { l: "CRITICAL EVENTS", v: threatStats.critical, c: "#ef4444" }].map((s, i) => <Card key={i} color={s.c} style={{ textAlign: "center", padding: 16 }}><div style={{ fontSize: 28, fontWeight: 900, color: s.c, fontFamily: "'Syne',sans-serif" }}>{s.v}</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 4 }}>{s.l}</div></Card>)}</div>
                    <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 10 }}>WEEKLY THREAT BREAKDOWN</div><div style={{ display: "flex", gap: 14, marginBottom: 10, flexWrap: "wrap" }}>{threatTypeStats.map((t) => <span key={t.name} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 8, color: "#253d5e" }}><span style={{ width: 9, height: 9, borderRadius: 2, background: t.c, display: "inline-block" }} />{t.name}</span>)}</div><ResponsiveContainer width="100%" height={180}><BarChart data={WEEKLY} margin={{ top: 5, right: 5, bottom: 5, left: -22 }}><CartesianGrid strokeDasharray="3 3" stroke="#060e18" /><XAxis dataKey="d" tick={{ fill: "#253d5e", fontSize: 9 }} /><YAxis tick={{ fill: "#1a3050", fontSize: 9 }} /><Tooltip content={<TT />} /><Bar dataKey="c" fill="#f97316" radius={[3, 3, 0, 0]} name="Cryptominer" /><Bar dataKey="n" fill="#eab308" radius={[3, 3, 0, 0]} name="Network" /><Bar dataKey="a" fill="#3b82f6" radius={[3, 3, 0, 0]} name="Anomaly" /><Bar dataKey="r" fill="#ef4444" radius={[3, 3, 0, 0]} name="Ransomware" /></BarChart></ResponsiveContainer></Card>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 13 }}>
                        <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>CPU vs RAM CORRELATION</div><ResponsiveContainer width="100%" height={140}><LineChart data={history.slice(-20)} margin={{ top: 5, right: 5, bottom: 0, left: -22 }}><CartesianGrid strokeDasharray="3 3" stroke="#060e18" /><XAxis dataKey="time" tick={{ fill: "#1a3050", fontSize: 8 }} interval={4} /><YAxis domain={[0, 100]} tick={{ fill: "#1a3050", fontSize: 8 }} /><Tooltip content={<TT />} /><Line type="monotone" dataKey="cpu" stroke="#3b82f6" strokeWidth={2} dot={false} name="CPU" /><Line type="monotone" dataKey="ram" stroke="#8b5cf6" strokeWidth={2} dot={false} name="RAM" /></LineChart></ResponsiveContainer></Card>
                        <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>SEVERITY BREAKDOWN</div><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, alignItems: "center" }}><ResponsiveContainer width="100%" height={120}><PieChart><Pie data={severityStats.filter(e => e.v > 0)} cx="50%" cy="50%" innerRadius={28} outerRadius={52} paddingAngle={4} dataKey="v">{severityStats.filter(e => e.v > 0).map((e, i) => <Cell key={i} fill={e.c} stroke="#0a1020" strokeWidth={2} />)}</Pie><Tooltip content={<TT />} /></PieChart></ResponsiveContainer><div style={{ display: "flex", flexDirection: "column", gap: 7 }}>{severityStats.map((s, i) => <div key={i}><div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}><span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 8, color: "#475569" }}><span style={{ width: 7, height: 7, borderRadius: 2, background: s.c, display: "inline-block" }} />{s.name}</span><span style={{ fontSize: 8, fontWeight: 700, color: s.c }}>{s.v}%</span></div><div style={{ height: 2, background: "#060e18", borderRadius: 999, overflow: "hidden" }}><div style={{ height: "100%", width: `${s.v}%`, background: `linear-gradient(90deg,${s.c}50,${s.c})`, borderRadius: 999 }} /></div></div>)}<div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 5, marginTop: 4 }}>{[{ l: "CRIT", v: threatStats.critical, c: "#ef4444" }, { l: "HIGH", v: threats.filter(t => t.sev === "HIGH").length, c: "#f97316" }, { l: "MED", v: threats.filter(t => t.sev === "MEDIUM").length, c: "#06b6d4" }, { l: "LOW", v: threats.filter(t => t.sev === "LOW").length, c: "#22c55e" }].map((s, i) => <div key={i} style={{ background: `${s.c}07`, border: `1px solid ${s.c}14`, borderRadius: 7, padding: "5px 8px", textAlign: "center" }}><div style={{ fontSize: 13, fontWeight: 900, color: s.c, fontFamily: "'Syne',sans-serif" }}>{s.v}</div><div style={{ fontSize: 6, color: s.c, opacity: .6, letterSpacing: 1 }}>{s.l}</div></div>)}</div></div></div></Card>
                    </div>
                </div>}

                {/* ── PACKETS ── */}
                {tab === "packets" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}><div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>PACKET INSPECTOR</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>WIRESHARK-STYLE LIVE ANALYSIS · {packets.length} PACKETS · {suspPkts.length} SUSPICIOUS</div></div><div style={{ display: "flex", gap: 8, alignItems: "center" }}><div style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", background: "rgba(249,115,22,.07)", border: "1px solid rgba(249,115,22,.18)", borderRadius: 9 }}><div style={{ width: 5, height: 5, borderRadius: "50%", background: "#f97316", animation: "pulse 2s infinite" }} /><span style={{ fontSize: 8, color: "#f97316", fontWeight: 700, letterSpacing: 1 }}>DEMO MODE</span></div><button onClick={handleExport} style={{ padding: "6px 14px", borderRadius: 9, background: "rgba(59,130,246,.07)", border: "1px solid rgba(59,130,246,.18)", color: "#3b82f6", fontSize: 8, cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", letterSpacing: 1 }}>📥 EXPORT PCAP</button></div></div>
                    {exportMsg && <div style={{ padding: "10px 14px", background: "rgba(59,130,246,.07)", border: "1px solid rgba(59,130,246,.18)", borderRadius: 10, fontSize: 10, color: "#60a5fa" }}>{exportMsg}</div>}
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 13 }}>
                        <SC icon="📦" label="TOTAL CAPTURED" value={packets.length} color="#3b82f6" />
                        <SC icon="🚨" label="SUSPICIOUS" value={suspPkts.length} color="#ef4444" />
                        <SC icon="📡" label="PROTOCOLS" value={protoStats.length} color="#8b5cf6" />
                        <SC icon="🔍" label="THREAT TYPES" value={threatTypeStats.length} color="#f97316" />
                    </div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 13 }}>
                        <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>PROTOCOL DISTRIBUTION</div><div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, alignItems: "center" }}><ResponsiveContainer width="100%" height={120}><PieChart><Pie data={protoStats} cx="50%" cy="50%" innerRadius={28} outerRadius={52} paddingAngle={3} dataKey="v">{protoStats.map((e, i) => <Cell key={i} fill={e.c} stroke="#0a1020" strokeWidth={2} />)}</Pie><Tooltip content={<TT />} /></PieChart></ResponsiveContainer><div style={{ display: "flex", flexDirection: "column", gap: 5 }}>{protoStats.map((e, i) => <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><span style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 8, color: "#475569" }}><span style={{ width: 6, height: 6, borderRadius: 2, background: e.c, display: "inline-block" }} />{e.name}</span><span style={{ fontSize: 8, fontWeight: 700, color: e.c }}>{e.v}%</span></div>)}</div></div></Card>
                        <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>THREAT TYPE DISTRIBUTION</div><ResponsiveContainer width="100%" height={140}><BarChart data={threatTypeStats} margin={{ top: 5, right: 5, bottom: 5, left: -22 }} layout="vertical"><CartesianGrid strokeDasharray="3 3" stroke="#060e18" /><XAxis type="number" tick={{ fill: "#1a3050", fontSize: 8 }} /><YAxis type="category" dataKey="name" tick={{ fill: "#475569", fontSize: 8 }} width={80} /><Tooltip content={<TT />} /><Bar dataKey="v" radius={[0, 3, 3, 0]} name="Count">{threatTypeStats.map((e, i) => <Cell key={i} fill={e.c} />)}</Bar></BarChart></ResponsiveContainer></Card>
                    </div>
                    {suspPkts.length > 0 && <Card color="#ef4444" glow style={{ padding: 16 }}><div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}><Pulse color="#ef4444" size={8} /><span style={{ fontSize: 7, fontWeight: 700, color: "#ef4444", letterSpacing: 3 }}>SUSPICIOUS ACTIVITY ALERTS</span></div>{suspPkts.slice(0, 5).map((p, i) => { const tc = THREAT_COLORS[p.threat_type] || "#eab308"; return (<div key={i} style={{ padding: "8px 0", borderBottom: "1px solid #060e18", display: "flex", justifyContent: "space-between", alignItems: "center" }}><div style={{ display: "flex", alignItems: "center", gap: 8, flex: 1, minWidth: 0 }}><Pill color={PROTO_COLORS[p.protocol] || "#3b82f6"}>{p.protocol}</Pill><div style={{ minWidth: 0 }}><div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}><span style={{ fontSize: 9, fontWeight: 700, color: tc }}>{(p.threat_type || "").replace(/_/g, " ")}</span>{MITRE[p.threat_type] && <span style={{ fontSize: 7, color: "#1a3050" }}>MITRE {MITRE[p.threat_type]}</span>}</div><p style={{ fontSize: 9, color: "#253d5e", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.src_ip}:{p.src_port} → {p.dst_ip}:{p.dst_port} · {fmtBytes(p.length)}</p></div></div><div style={{ textAlign: "right", flexShrink: 0, marginLeft: 10 }}><div style={{ fontSize: 10, fontWeight: 700, color: tc, fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(p.timestamp)}</div><div style={{ fontSize: 8, color: "#1a3050", marginTop: 1 }}>{p.confidence}% conf</div></div></div>); })}</Card>}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}><div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>{["ALL", "SUSPICIOUS", "NORMAL"].map(f => <FB key={f} active={pFilter === f} onClick={() => setPF(f)}>{f}</FB>)}<span style={{ width: 1, background: "#0e1d33", margin: "0 3px" }} />{["ALL", "TCP", "UDP", "DNS", "ICMP", "HTTPS", "HTTP"].map(p => <FB key={p} active={pProto === p} color={PROTO_COLORS[p] || "#3b82f6"} onClick={() => setPP(p)}>{p}</FB>)}</div><span style={{ fontSize: 8, color: "#1a3050" }}>{filteredP.length} packets</span></div>
                    <Card style={{ padding: 0, overflow: "hidden" }}><table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}><thead><tr style={S.thead}>{[["TIME", 10], ["PROTO", 8], ["SOURCE", 18], ["DESTINATION", 18], ["SIZE", 8], ["FLAGS", 8], ["THREAT", 22], ["CONF", 8]].map(([h, w]) => <th key={h} style={{ ...S.th, textAlign: ["SIZE", "CONF"].includes(h) ? "right" : "left", width: `${w}%` }}>{h}</th>)}</tr></thead><tbody>{filteredP.slice(0, 80).map((p, i) => <PacketRow key={i} pkt={p} />)}{filteredP.length === 0 && <tr><td colSpan={8} style={{ textAlign: "center", padding: "40px 0", color: "#1a3050", fontSize: 8, letterSpacing: 3 }}>NO PACKETS MATCH FILTER</td></tr>}</tbody></table></Card>
                </div>}

                {/* ── PROCESSES ── */}
                {tab === "processes" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}><div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>PROCESS MONITOR</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>REAL-TIME RISK ANALYSIS · {processes.length || PROCS.length} PROCESSES</div></div><div style={{ display: "flex", gap: 7 }}><Pill color="#ef4444">{processes.filter(p => p.risk > 70).length} HIGH RISK</Pill><Pill color="#253d5e">{processes.length || PROCS.length} TOTAL</Pill></div></div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 13 }}>{[{ l: "CRITICAL >70", n: processes.filter(p => p.risk > 70).length, c: "#ef4444" }, { l: "MEDIUM 40–70", n: processes.filter(p => p.risk > 40 && p.risk <= 70).length, c: "#f97316" }, { l: "SAFE <40", n: processes.filter(p => p.risk <= 40).length, c: "#22c55e" }].map((r, i) => <Card key={i} color={r.c} style={{ display: "flex", alignItems: "center", gap: 11, padding: 13 }}><div style={{ width: 7, height: 7, borderRadius: "50%", background: r.c, flexShrink: 0 }} /><div><div style={{ fontSize: 20, fontWeight: 900, color: r.c, fontFamily: "'Syne',sans-serif" }}>{r.n}</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 1.5, marginTop: 2 }}>{r.l}</div></div></Card>)}</div>
                    <Card style={{ padding: 0, overflow: "hidden" }}><table style={{ width: "100%", borderCollapse: "collapse", tableLayout: "fixed" }}><thead><tr style={S.thead}>{[["PROCESS", 34], ["PID", 11], ["CPU %", 13], ["RAM %", 13], ["RISK SCORE", 29]].map(([h, w]) => <th key={h} style={{ ...S.th, textAlign: h === "PROCESS" ? "left" : "right", width: `${w}%` }}>{h}</th>)}</tr></thead><tbody>{[...(processes.length > 0 ? processes : PROCS)].sort((a, b) => b.risk - a.risk).map((p, i) => <ProcRow key={i} p={p} />)}</tbody></table></Card>
                </div>}

                {/* ── NETWORK ── */}
                {tab === "network" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>NETWORK MONITOR</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>LIVE TRAFFIC ANALYSIS & ANOMALY DETECTION</div></div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 13 }}>{[{ l: "BYTES RECEIVED", v: fmtBytes(metricsData?.network?.bytes_recv || 0), i: "📥", c: "#3b82f6" }, { l: "BYTES SENT", v: fmtBytes(metricsData?.network?.bytes_sent || 0), i: "📤", c: "#8b5cf6" }, { l: "ACTIVE CONNS", v: activeConns, i: "🔗", c: "#22d3ee" }, { l: "SUSPICIOUS", v: suspPkts.length, i: "🔒", c: suspPkts.length > 0 ? "#ef4444" : "#22c55e" }].map((s, i) => <Card key={i} color={s.c} style={{ textAlign: "center", padding: 16 }}><div style={{ fontSize: 20, marginBottom: 7 }}>{s.i}</div><div style={{ fontSize: 18, fontWeight: 900, color: s.c, fontFamily: "'Syne',sans-serif" }}>{s.v}</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>{s.l}</div></Card>)}</div>
                    <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>NETWORK ACTIVITY TIMELINE</div><ResponsiveContainer width="100%" height={150}><AreaChart data={history} margin={{ top: 5, right: 5, bottom: 0, left: -22 }}><defs><linearGradient id="gnet4" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#22d3ee" stopOpacity={.12} /><stop offset="95%" stopColor="#22d3ee" stopOpacity={0} /></linearGradient></defs><CartesianGrid strokeDasharray="3 3" stroke="#060e18" /><XAxis dataKey="time" tick={{ fill: "#1a3050", fontSize: 8 }} interval={7} /><YAxis domain={[0, 100]} tick={{ fill: "#1a3050", fontSize: 8 }} /><Tooltip content={<TT />} /><Area type="monotone" dataKey="net" stroke="#22d3ee" fill="url(#gnet4)" strokeWidth={1.5} dot={false} name="Network %" /></AreaChart></ResponsiveContainer></Card>
                    <Card><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 3, marginBottom: 12 }}>SUSPICIOUS CONNECTIONS</div><div style={{ textAlign: "center", padding: "24px 0" }}><div style={{ width: 38, height: 38, borderRadius: "50%", background: suspPkts.length > 0 ? "rgba(239,68,68,.06)" : "rgba(34,197,94,.06)", border: `1px solid ${suspPkts.length > 0 ? "rgba(239,68,68,.13)" : "rgba(34,197,94,.13)"}`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 10px", fontSize: 17 }}>{suspPkts.length > 0 ? "⚠️" : "✅"}</div><div style={{ fontSize: 10, color: suspPkts.length > 0 ? "#ef4444" : "#1a3050", letterSpacing: 2 }}>{suspPkts.length > 0 ? `${suspPkts.length} SUSPICIOUS CONNECTIONS DETECTED` : "NO SUSPICIOUS CONNECTIONS"}</div><div style={{ fontSize: 8, color: "#0d1e33", marginTop: 4 }}>{suspPkts.length > 0 ? "Review packet details for analysis" : `All ${activeConns} active connections verified safe`}</div></div></Card>
                </div>}

                {/* ── TIMELINE ── */}
                {tab === "timeline" && <div style={{ display: "flex", flexDirection: "column", gap: 16, animation: "fadeUp .3s ease" }}>
                    <div><div style={{ fontFamily: "'Syne',sans-serif", fontSize: 17, fontWeight: 900, letterSpacing: 3, color: "#c8d8f0" }}>THREAT TIMELINE</div><div style={{ fontSize: 7, color: "#1a3050", letterSpacing: 2, marginTop: 3 }}>CHRONOLOGICAL INCIDENT LOG WITH EXACT TIMESTAMPS</div></div>
                    {[...threats].sort((a, b) => new Date(b.ts) - new Date(a.ts)).map((t, i, arr) => { const c = SEV_COLORS[t.sev] || "#eab308"; return (<div key={t.id} style={{ display: "flex", gap: 0, position: "relative" }}><div style={{ display: "flex", flexDirection: "column", alignItems: "center", width: 38, flexShrink: 0 }}><div style={{ width: 11, height: 11, borderRadius: "50%", background: t.status === "ACTIVE" ? c : "#1a3050", border: `2px solid ${t.status === "ACTIVE" ? c + "40" : "#0e1d33"}`, position: "relative", zIndex: 1, marginTop: 16, flexShrink: 0 }} />{i < arr.length - 1 && <div style={{ width: 1, flex: 1, background: `linear-gradient(180deg,${c}25,#0e1d33)`, minHeight: 20 }} />}</div><div style={{ flex: 1, margin: "8px 0 8px 8px", background: "linear-gradient(150deg,#0a1020,#07101c)", border: `1px solid ${c}18`, borderRadius: "0 14px 14px 0", padding: "13px 15px", transition: "border-color .2s" }} onMouseEnter={e => e.currentTarget.style.borderColor = c + "35"} onMouseLeave={e => e.currentTarget.style.borderColor = c + "18"}><div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}><div style={{ display: "flex", alignItems: "center", gap: 8 }}><span style={{ fontSize: 15 }}>{t.icon}</span><div><div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}><span style={{ color: "#c8d8f0", fontSize: 10, fontWeight: 700 }}>{t.type}</span><Pill color={c}>{t.sev}</Pill><Pill color={t.status === "ACTIVE" ? "#ef4444" : "#22c55e"}>{t.status}</Pill></div><p style={{ color: "#475569", fontSize: 9, marginTop: 3, lineHeight: 1.5 }}>{t.desc.substring(0, 85)}...</p></div></div><div style={{ textAlign: "right", flexShrink: 0 }}><div style={{ fontSize: 11, fontWeight: 900, color: c, fontFamily: "'JetBrains Mono',monospace" }}>{fmtTime(t.ts)}</div><div style={{ fontSize: 8, color: "#253d5e", marginTop: 2 }}>{fmtDate(t.ts)}</div><div style={{ fontSize: 7, color: "#1a3050", marginTop: 1 }}>{timeAgo(t.ts)}</div></div></div><div style={{ marginTop: 9, display: "flex", alignItems: "center", gap: 7 }}><div style={{ flex: 1, height: 2, background: "#060e18", borderRadius: 999, overflow: "hidden" }}><div style={{ height: "100%", width: `${t.conf}%`, background: `linear-gradient(90deg,${c}45,${c})`, borderRadius: 999 }} /></div><span style={{ fontSize: 8, color: c, fontWeight: 700 }}>{t.conf}% confidence</span></div></div></div>); })}
                </div>}

            </main>
        </div>

        <footer style={{ borderTop: "1px solid #080f1c", padding: "8px 20px", display: "flex", justifyContent: "space-between", fontSize: 7, color: "#0d1e33", letterSpacing: 2, background: "#030810" }}>
            <span>SENTINEL v3.0 · AI-POWERED ENDPOINT SECURITY + PACKET INSPECTION</span>
            <span>UPDATED: {time} · INTERVAL: 5s · {connected ? "BACKEND CONNECTED" : "DEMO MODE"}</span>
        </footer>
    </div>);
}
