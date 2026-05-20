"""
SENTINEL - FastAPI Backend Server (MongoDB Edition)
====================================================
Serves real-time data to the React dashboard.
Uses MongoDB for scalable threat storage.

Run with: uvicorn backend.server_mongo:app --reload --port 8000

MongoDB Configuration:
    - Local: MongoDB running on localhost:27017
    - Atlas: Set MONGODB_URI environment variable
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
from database.mongo_manager import get_mongo, close_mongo

app = FastAPI(title="SENTINEL API (MongoDB)", version="2.0.0")

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
detector = EnhancedThreatDetector()
network_detector = NetworkThreatDetector()
latest_snapshot = {}
active_connections = []
auto_response_log = []

# MongoDB instance
mongo = None


def init_mongodb():
    """Initialize MongoDB connection"""
    global mongo
    
    # Check for environment variable (useful for Atlas)
    conn_string = os.environ.get("MONGODB_URI", "mongodb://localhost:27017/")
    db_name = os.environ.get("MONGODB_DB", "sentinel")
    
    try:
        mongo = get_mongo(conn_string, db_name)
        print(f"[OK] MongoDB connected: {conn_string} -> {db_name}")
    except Exception as e:
        print(f"[WARNING] MongoDB not available: {e}")
        print("[WARNING] Falling back to SQLite (database/db_manager.py)")
        mongo = None


@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    init_mongodb()
    
    # Start packet capture
    if agent.packet_capture_enabled:
        agent.start_packet_monitoring()
        print("[SENTINEL] Packet inspection enabled")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    close_mongo()
    print("[SENTINEL] MongoDB connection closed")


@app.get("/")
def root():
    db_type = "MongoDB" if mongo else "SQLite"
    return {
        "status": "SENTINEL is running",
        "version": "2.0.0 (MongoDB)",
        "database": db_type
    }


@app.get("/api/metrics/live")
def get_live_metrics():
    """Get current system metrics with auto-response"""
    try:
        snapshot = agent.collect_all()
        system = snapshot["system"]
        network = snapshot["network"]

        # Save to MongoDB
        if mongo:
            mongo.save_metrics(system, network)
        else:
            from database.db_manager import save_metrics
            save_metrics(system, network)

        # Run enhanced threat detection
        detection = detector.analyze(snapshot, auto_respond=True)

        # Save threats
        for threat in detection.threats:
            if mongo:
                mongo.save_threat(threat)
            else:
                from database.db_manager import save_threat
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
    try:
        if mongo:
            return {"metrics": mongo.get_recent_metrics(limit)}
        else:
            from database.db_manager import get_recent_metrics
            return {"metrics": get_recent_metrics(limit)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/processes")
def get_processes():
    """Get all running processes with risk scores"""
    try:
        snapshot = agent.collect_all()
        processes = snapshot["processes"]
        processes.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        return {
            "processes": processes[:50],
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
        return snapshot["network"]
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/threats")
def get_threats(status: str = None):
    """Get all detected threats"""
    try:
        if mongo:
            threats = mongo.get_all_threats(limit=100, status=status)
        else:
            from database.db_manager import get_all_threats
            threats = get_all_threats(status)
        
        return {
            "threats": threats,
            "total": len(threats),
            "active": len([t for t in threats if t.get("status") == "ACTIVE"]),
            "critical": len([t for t in threats if t.get("severity") == "CRITICAL"]),
            "high": len([t for t in threats if t.get("severity") == "HIGH"])
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/threats/{threat_id}")
def get_threat(threat_id: str):
    """Get single threat by ID"""
    try:
        if mongo:
            threat = mongo.get_threat_by_id(threat_id)
            if threat:
                return {"threat": threat}
            return JSONResponse(status_code=404, content={"error": "Threat not found"})
        else:
            return JSONResponse(status_code=501, content={"error": "Not available in SQLite mode"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/threats/{threat_id}/resolve")
def resolve_threat_endpoint(threat_id: str):
    """Mark a threat as resolved"""
    try:
        if mongo:
            mongo.resolve_threat(threat_id)
        else:
            from database.db_manager import resolve_threat
            resolve_threat(threat_id)
        return {"status": "resolved", "threat_id": threat_id}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/summary")
def get_summary():
    """Get overall system health summary"""
    try:
        if mongo:
            metrics = mongo.get_metrics_summary(hours=24)
            threats = mongo.get_all_threats(limit=100, status="ACTIVE")
        else:
            from database.db_manager import get_metrics_summary, get_all_threats
            metrics = get_metrics_summary()
            threats = get_all_threats("ACTIVE")

        health_score = _calculate_health_score(metrics, threats)

        return {
            "health_score": health_score,
            "metrics_summary": metrics,
            "active_threats": len(threats),
            "system_status": "CRITICAL" if len(threats) > 3
                           else "WARNING" if len(threats) > 0
                           else "SAFE",
            "uptime": "Monitoring active",
            "last_updated": datetime.datetime.utcnow().isoformat(),
            "auto_responses_today": len(auto_response_log),
            "database": "MongoDB" if mongo else "SQLite"
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


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
    try:
        if mongo:
            history = mongo.get_auto_response_history(limit=100)
        else:
            from database.db_manager import get_auto_response_history
            history = db_get_auto_response_history()
        
        return {
            "history": history if mongo else auto_response_log[-100:],
            "total": len(history) if mongo else len(auto_response_log),
            "by_action": {
                "SUSPEND_PROCESS": len([r for r in (history if mongo else auto_response_log) if r.get("action") == "SUSPEND_PROCESS"]),
                "BLOCK_IP": len([r for r in (history if mongo else auto_response_log) if r.get("action") == "BLOCK_IP"]),
                "ISOLATE_AND_ALERT": len([r for r in (history if mongo else auto_response_log) if r.get("action") == "ISOLATE_AND_ALERT"]),
                "LOCKDOWN": len([r for r in (history if mongo else auto_response_log) if r.get("action") == "LOCKDOWN"]),
                "QUARANTINE_FILE": len([r for r in (history if mongo else auto_response_log) if r.get("action") == "QUARANTINE_FILE"]),
                "OTHER": len([r for r in (history if mongo else auto_response_log) if r.get("action") not in ["SUSPEND_PROCESS", "BLOCK_IP", "ISOLATE_AND_ALERT", "LOCKDOWN", "QUARANTINE_FILE"]])
            }
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/auto-response/quarantine")
def get_quarantine_status():
    """Get quarantine status and files"""
    try:
        if mongo:
            quarantine = mongo.get_quarantine_list(limit=50)
            return {"quarantined_files": quarantine, "total": len(quarantine)}
        else:
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
        if mongo:
            packets = mongo.get_recent_packets(limit=limit)
        else:
            from database.db_manager import get_recent_packets
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
        if mongo:
            packets = mongo.get_suspicious_packets(limit=limit)
        else:
            from database.db_manager import get_recent_packets
            packets = get_recent_packets(limit=limit, suspicious_only=True)
        
        return {"packets": packets, "total": len(packets)}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/packets/statistics")
def get_packet_stats():
    """Get packet capture statistics"""
    try:
        if mongo:
            stats = mongo.get_packet_statistics()
        else:
            from database.db_manager import get_packet_statistics
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
        if mongo:
            stats = mongo.get_packet_statistics()
        else:
            from database.db_manager import get_packet_statistics
            stats = get_packet_statistics()
        
        return {
            "period": f"Last {hours} hour(s)",
            "total_packets": stats.get('total', 0),
            "suspicious_packets": stats.get('suspicious', 0),
            "protocols": stats.get('by_protocol', {}),
            "threat_types": stats.get('by_type', {})
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/database/stats")
def get_database_stats():
    """Get database statistics (MongoDB only)"""
    try:
        if mongo:
            stats = mongo.get_collection_stats()
            return {
                "database": "MongoDB",
                "collections": stats,
                "connection": "active"
            }
        else:
            return {
                "database": "SQLite",
                "connection": "active",
                "note": "Use /api/summary for SQLite stats"
            }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.post("/api/database/cleanup")
def cleanup_old_data(days: int = 30):
    """Clean up old data (MongoDB only)"""
    try:
        if mongo:
            deleted = mongo.clear_old_data(days=days)
            return {
                "status": "success",
                "deleted_records": deleted,
                "older_than_days": days
            }
        else:
            return JSONResponse(status_code=501, content={"error": "Only available with MongoDB"})
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time live data streaming"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            try:
                snapshot = agent.collect_all()
                detection = detector.analyze(snapshot)

                # Save to database
                if mongo:
                    mongo.save_metrics(snapshot["system"], snapshot["network"])
                    for threat in detection.threats:
                        mongo.save_threat(threat)
                else:
                    from database.db_manager import save_metrics, save_threat
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
                    "timestamp": snapshot["snapshot_time"],
                    "database": "MongoDB" if mongo else "SQLite"
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
        if websocket in active_connections:
            active_connections.remove(websocket)
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    print("[SENTINEL] Starting SENTINEL Backend Server (MongoDB Edition)...")
    print("[SENTINEL] Dashboard API: http://localhost:8000")
    print("[SENTINEL] API Docs: http://localhost:8000/docs")
    print("[SENTINEL] Database: MongoDB (mongodb://localhost:27017/)")
    print("[SENTINEL] To use MongoDB Atlas, set MONGODB_URI environment variable")
    uvicorn.run(app, host="0.0.0.0", port=8000)
