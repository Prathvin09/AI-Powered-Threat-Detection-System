"""
SENTINEL - FastAPI Backend Server
Serves real-time data to the React dashboard
Run with: uvicorn backend.server:app --reload --port 8000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import json
import datetime
import random

from agent.collector import SentinelAgent
from ml_engine.enhanced_detector import EnhancedThreatDetector
from ml_engine.network_detector import NetworkThreatDetector, create_network_threat_alert
from database.db_manager import (
    init_db, save_metrics, save_threat, save_packet_event,
    get_recent_metrics, get_all_threats, get_metrics_summary,
    resolve_threat, get_packet_statistics, get_recent_packets,
    get_auto_response_history as db_get_auto_response_history
)

app = FastAPI(title="SENTINEL API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
agent = SentinelAgent(enable_packet_capture=True, packet_config={
    'sample_rate': 0.5,
    'lightweight_mode': False
})
detector = EnhancedThreatDetector()  # Enhanced: false positive filtering + threat prioritization
network_detector = NetworkThreatDetector()  # Packet-level threat detection
latest_snapshot = {}
active_connections = []
auto_response_log = []  # Track executed auto-responses

# Initialize DB on startup
init_db()

# Start packet capture
if agent.packet_capture_enabled:
    agent.start_packet_monitoring()
    print("[SENTINEL] Packet inspection enabled")


@app.get("/")
def root():
    return {"status": "SENTINEL is running", "version": "1.0.0"}


@app.get("/api/metrics/live")
def get_live_metrics():
    """Get current system metrics with auto-response"""
    try:
        snapshot = agent.collect_all()
        system = snapshot["system"]
        network = snapshot["network"]

        # Save to DB
        save_metrics(system, network)

        # Run enhanced threat detection with false positive filtering
        detection = detector.analyze(snapshot, auto_respond=True)

        # Save genuine threats (already filtered) and log auto-responses
        for threat in detection.threats:
            save_threat(threat)
            if threat.get("auto_response_executed"):
                auto_response_log.append({
                    "threat_id": threat.get("id"),
                    "threat_type": threat.get("type"),
                    "action": threat.get("auto_action"),
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "success": threat.get("auto_response_success", False),
                    "message": threat.get("auto_response_message", "")
                })

        health = detector.get_system_health()

        return {
            "system": {
                "cpu_percent": system["cpu_percent"],
                "ram_percent": system["ram_percent"],
                "disk_percent": system["disk_percent"],
                "battery_percent": system.get("battery_percent"),
                "hostname": system.get("hostname"),
                "os": system.get("os"),
                "timestamp": system["timestamp"]
            },
            "network": {
                "bytes_sent": network["bytes_sent"],
                "bytes_recv": network["bytes_recv"],
                "active_connections": len(network["connections"]),
                "suspicious_connections": len(network["suspicious_connections"])
            },
            "detection": {
                "system_status": detection.system_status,
                "anomaly_score": detection.anomaly_score,
                "anomaly_reason": detection.anomaly_reason,
                "is_baseline_ready": health["baseline_ready"],
                "baseline_progress": health["baseline_progress"],
                "active_threats": len(detection.threats),
                "new_threats": detection.threats,
                "false_positives_filtered": detection.statistics.get("false_positives_filtered", 0),
                "auto_responses_executed": len([t for t in detection.threats if t.get("auto_response_executed")])
            },
            "processes_count": len(snapshot["processes"]),
            "high_risk_processes": len([p for p in snapshot["processes"]
                                        if p.get("risk_score", 0) > 70])
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/metrics/history")
def get_metrics_history(limit: int = 60):
    """Get historical metrics for charts"""
    return get_recent_metrics(limit)


@app.get("/api/processes")
def get_processes():
    """Get all running processes with risk scores"""
    try:
        snapshot = agent.collect_all()
        processes = snapshot["processes"]
        # Sort by risk score descending
        processes.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return {
            "processes": processes[:50],  # Top 50
            "total": len(processes),
            "high_risk": len([p for p in processes if p.get("risk_score", 0) > 70]),
            "medium_risk": len([p for p in processes if 40 < p.get("risk_score", 0) <= 70]),
            "safe": len([p for p in processes if p.get("risk_score", 0) <= 40])
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/network")
def get_network():
    """Get network connections"""
    try:
        snapshot = agent.collect_all()
        network = snapshot["network"]
        return network
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/threats")
def get_threats(status: str = None):
    """Get all detected threats"""
    threats = get_all_threats(status)
    return {
        "threats": threats,
        "total": len(threats),
        "active": len([t for t in threats if t.get("status") == "ACTIVE"]),
        "critical": len([t for t in threats if t.get("severity") == "CRITICAL"]),
        "high": len([t for t in threats if t.get("severity") == "HIGH"])
    }


@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat_endpoint(threat_id: str):
    """Mark a threat as resolved"""
    resolve_threat(threat_id)
    return {"status": "resolved", "threat_id": threat_id}


@app.get("/api/summary")
def get_summary():
    """Get overall system health summary"""
    metrics = get_metrics_summary()
    threats = get_all_threats("ACTIVE")

    return {
        "health_score": _calculate_health_score(metrics, threats),
        "metrics_summary": metrics,
        "active_threats": len(threats),
        "system_status": "CRITICAL" if len(threats) > 3
                         else "WARNING" if len(threats) > 0
                         else "SAFE",
        "uptime": "Monitoring active",
        "last_updated": datetime.datetime.utcnow().isoformat(),
        "auto_responses_today": len(auto_response_log)
    }


def _calculate_health_score(metrics, threats):
    score = 100
    score -= len(threats) * 15
    avg_cpu = metrics.get("avg_cpu") or 0
    avg_ram = metrics.get("avg_ram") or 0
    if avg_cpu > 80:
        score -= 20
    elif avg_cpu > 60:
        score -= 10
    if avg_ram > 80:
        score -= 15
    return max(0, min(100, score))


@app.get("/api/auto-response/history")
def get_auto_response_history():
    """Get history of executed auto-responses"""
    return {
        "history": auto_response_log[-100:],  # Last 100 responses
        "total": len(auto_response_log),
        "by_action": {
            "SUSPEND_PROCESS": len([r for r in auto_response_log if r["action"] == "SUSPEND_PROCESS"]),
            "BLOCK_IP": len([r for r in auto_response_log if r["action"] == "BLOCK_IP"]),
            "ISOLATE_AND_ALERT": len([r for r in auto_response_log if r["action"] == "ISOLATE_AND_ALERT"]),
            "LOCKDOWN": len([r for r in auto_response_log if r["action"] == "LOCKDOWN"]),
            "QUARANTINE_FILE": len([r for r in auto_response_log if r["action"] == "QUARANTINE_FILE"]),
            "OTHER": len([r for r in auto_response_log if r["action"] not in ["SUSPEND_PROCESS", "BLOCK_IP", "ISOLATE_AND_ALERT", "LOCKDOWN", "QUARANTINE_FILE"]])
        }
    }


@app.get("/api/auto-response/quarantine")
def get_quarantine_status():
    """Get quarantine status and files"""
    try:
        quarantine_info = detector.get_quarantine_status()
        return quarantine_info
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/auto-response/rollback/{action_index}")
def rollback_auto_response(action_index: int):
    """Rollback a specific auto-response action"""
    try:
        result = detector.rollback_action(action_index)
        return result
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": f"Invalid action index: {str(e)}"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


# ============================================================================
# PACKET INSPECTION API ENDPOINTS
# ============================================================================

@app.get("/api/packets/live")
def get_live_packets(limit: int = 100):
    """Get recent live packets"""
    try:
        packets = get_recent_packets(limit=limit, suspicious_only=False)
        return {
            "packets": packets,
            "total": len(packets),
            "suspicious_count": len([p for p in packets if p.get('is_suspicious')])
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/packets/suspicious")
def get_suspicious_packets(limit: int = 50):
    """Get suspicious packets only"""
    try:
        packets = get_recent_packets(limit=limit, suspicious_only=True)
        return {
            "packets": packets,
            "total": len(packets)
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/packets/statistics")
def get_packet_stats():
    """Get packet capture statistics"""
    try:
        stats = get_packet_statistics()
        agent_stats = agent.get_packet_data()
        
        return {
            "database": stats,
            "live_capture": agent_stats['statistics'] if agent_stats else {},
            "protocol_distribution": agent_stats['protocol_distribution'] if agent_stats else {},
            "threat_summary": agent_stats['threat_summary'] if agent_stats else {}
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/packets/analysis")
def get_packet_analysis():
    """Get comprehensive packet analysis"""
    try:
        agent_data = agent.get_packet_data()
        detector_stats = network_detector.get_statistics()
        
        return {
            "capture_status": {
                "enabled": agent.packet_capture_enabled,
                "running": agent.packet_capture.running if agent.packet_capture else False,
                "sample_rate": agent.packet_capture.sample_rate if agent.packet_capture else 0,
                "lightweight_mode": agent.packet_capture.lightweight_mode if agent.packet_capture else False
            },
            "statistics": agent_data['statistics'] if agent_data else {},
            "protocol_distribution": agent_data['protocol_distribution'] if agent_data else {},
            "threat_summary": agent_data['threat_summary'] if agent_data else {},
            "detector_stats": detector_stats
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/packets/export")
def export_pcap(duration: int = 30):
    """Export packets to PCAP file"""
    try:
        if not agent.packet_capture:
            return JSONResponse(status_code=400, content={"error": "Packet capture not enabled"})
        
        output_file = agent.packet_capture.export_pcap(duration_seconds=duration)
        return {
            "status": "success",
            "file": output_file,
            "duration": duration,
            "message": f"Captured {duration} seconds of traffic"
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/network/traffic-history")
def get_traffic_history(hours: int = 1):
    """Get network traffic history"""
    try:
        stats = get_packet_statistics()
        return {
            "period": f"Last {hours} hour(s)",
            "total_packets": stats.get('total', 0),
            "suspicious_packets": stats.get('suspicious', 0),
            "protocols": stats.get('protocols', {}),
            "threat_types": stats.get('threat_types', {})
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time live data streaming"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Send live data every 5 seconds
            try:
                snapshot = agent.collect_all()
                detection = detector.analyze(snapshot)

                # Save metrics
                save_metrics(snapshot["system"], snapshot["network"])
                for threat in detection.threats:
                    save_threat(threat)

                data = {
                    "type": "LIVE_UPDATE",
                    "cpu": snapshot["system"]["cpu_percent"],
                    "ram": snapshot["system"]["ram_percent"],
                    "disk": snapshot["system"]["disk_percent"],
                    "network_in": snapshot["network"]["bytes_recv"],
                    "network_out": snapshot["network"]["bytes_sent"],
                    "status": detection.system_status,
                    "anomaly_score": detection.anomaly_score,
                    "new_threats": detection.threats,
                    "timestamp": snapshot["snapshot_time"]
                }
                await websocket.send_text(json.dumps(data))
            except Exception as e:
                error_data = {
                    "type": "ERROR",
                    "message": str(e)
                }
                try:
                    await websocket.send_text(json.dumps(error_data))
                except Exception:
                    break

            await asyncio.sleep(5)

    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        # Handle any other errors and cleanup
        if websocket in active_connections:
            active_connections.remove(websocket)
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    print("[SENTINEL] Starting SENTINEL Backend Server...")
    print("[SENTINEL] Dashboard API: http://localhost:8000")
    print("[SENTINEL] API Docs: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
