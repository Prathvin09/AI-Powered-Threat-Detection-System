"""
SENTINEL - MongoDB Manager
==========================
Alternative to SQLite for scalable threat storage and real-time analytics.

Features:
- Document-based storage (perfect for threat data)
- Automatic TTL for old data cleanup
- Advanced aggregation for analytics
- Cloud-ready (MongoDB Atlas support)
- High concurrency support

Usage:
    from database.mongo_manager import get_mongo
    mongo = get_mongo()
    mongo.save_threat(threat_data)
"""

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, DuplicateKeyError
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger('SENTINEL.MongoDB')


class MongoDBManager:
    """
    MongoDB database manager for SENTINEL threat detection system.
    Handles all database operations for threats, metrics, and events.
    """
    
    def __init__(self, 
                 connection_string: str = "mongodb://localhost:27017/",
                 db_name: str = "sentinel"):
        """
        Initialize MongoDB connection.
        
        Args:
            connection_string: MongoDB connection URI
                - Local: mongodb://localhost:27017/
                - Atlas: mongodb+srv://user:pass@cluster.mongodb.net/
            db_name: Database name (default: "sentinel")
        """
        self.connection_string = connection_string
        self.db_name = db_name
        
        try:
            self.client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=5000,
                socketTimeoutMS=45000,
                connectTimeoutMS=20000,
                retryWrites=True,
                w="majority"
            )
            
            # Test connection
            self.client.admin.command('ping')
            
            self.db = self.client[db_name]
            
            # Define collections
            self.metrics = self.db.metrics
            self.threats = self.db.threats
            self.processes = self.db.processes
            self.network_events = self.db.network_events
            self.packet_events = self.db.packet_events
            self.alerts = self.db.alerts
            self.auto_response = self.db.auto_response
            self.quarantine = self.db.quarantine
            
            # Create indexes for performance
            self._create_indexes()
            
            logger.info(f"MongoDB connected to {db_name} at {connection_string}")
            
        except ConnectionFailure as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
        except Exception as e:
            logger.error(f"MongoDB initialization error: {e}")
            raise
    
    def _create_indexes(self):
        """Create indexes for query performance and TTL"""
        try:
            # Threats indexes
            self.threats.create_index([("detected_at", DESCENDING)])
            self.threats.create_index([("type", ASCENDING)])
            self.threats.create_index([("severity", ASCENDING)])
            self.threats.create_index([("status", ASCENDING)])
            self.threats.create_index([("detected_at", DESCENDING)], 
                                      expireAfterSeconds=2592000)  # 30 days TTL
            
            # Metrics indexes (7 days TTL)
            self.metrics.create_index([("timestamp", DESCENDING)])
            self.metrics.create_index([("timestamp", DESCENDING)], 
                                      expireAfterSeconds=604800)  # 7 days TTL
            
            # Processes indexes
            self.processes.create_index([("timestamp", DESCENDING)])
            self.processes.create_index([("pid", ASCENDING)])
            self.processes.create_index([("risk_score", DESCENDING)])
            
            # Network events indexes
            self.network_events.create_index([("timestamp", DESCENDING)])
            self.network_events.create_index([("remote_ip", ASCENDING)])
            self.network_events.create_index([("is_suspicious", ASCENDING)])
            
            # Packet events indexes
            self.packet_events.create_index([("timestamp", DESCENDING)])
            self.packet_events.create_index([("src_ip", ASCENDING)])
            self.packet_events.create_index([("threat_type", ASCENDING)])
            
            # Auto response indexes
            self.auto_response.create_index([("executed_at", DESCENDING)])
            self.auto_response.create_index([("threat_id", ASCENDING)])
            
            # Quarantine indexes
            self.quarantine.create_index([("threat_type", ASCENDING)])
            self.quarantine.create_index([("quarantined_at", DESCENDING)])
            
            logger.debug("MongoDB indexes created successfully")
            
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")
    
    # ==================== METRICS ====================
    
    def save_metrics(self, system_data: Dict, network_data: Dict) -> bool:
        """Save system metrics"""
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "cpu_percent": system_data.get("cpu_percent", 0),
                "ram_percent": system_data.get("ram_percent", 0),
                "disk_percent": system_data.get("disk_percent", 0),
                "ram_used": system_data.get("ram_used", 0),
                "ram_total": system_data.get("ram_total", 0),
                "bytes_sent": network_data.get("bytes_sent", 0),
                "bytes_recv": network_data.get("bytes_recv", 0),
                "battery_percent": system_data.get("battery_percent"),
                "temperature": system_data.get("temperature", {})
            }
            self.metrics.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")
            return False
    
    def get_recent_metrics(self, limit: int = 100) -> List[Dict]:
        """Get recent system metrics"""
        try:
            metrics = list(self.metrics.find()
                          .sort("timestamp", DESCENDING)
                          .limit(limit))
            
            # Convert ObjectId to string and datetime to ISO format
            for m in metrics:
                m["_id"] = str(m["_id"])
                if "timestamp" in m:
                    m["timestamp"] = m["timestamp"].isoformat()
            
            return list(reversed(metrics))  # Return in chronological order
        except Exception as e:
            logger.error(f"Error getting metrics: {e}")
            return []
    
    def get_metrics_summary(self, hours: int = 24) -> Dict:
        """Get metrics summary for dashboard"""
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            
            pipeline = [
                {"$match": {"timestamp": {"$gte": cutoff}}},
                {"$group": {
                    "_id": None,
                    "avg_cpu": {"$avg": "$cpu_percent"},
                    "avg_ram": {"$avg": "$ram_percent"},
                    "avg_disk": {"$avg": "$disk_percent"},
                    "max_cpu": {"$max": "$cpu_percent"},
                    "max_ram": {"$max": "$ram_percent"},
                    "max_disk": {"$max": "$disk_percent"},
                    "count": {"$sum": 1}
                }}
            ]
            
            result = list(self.metrics.aggregate(pipeline))
            
            if result:
                return {
                    "avg_cpu": round(result[0].get("avg_cpu", 0), 2),
                    "avg_ram": round(result[0].get("avg_ram", 0), 2),
                    "avg_disk": round(result[0].get("avg_disk", 0), 2),
                    "max_cpu": round(result[0].get("max_cpu", 0), 2),
                    "max_ram": round(result[0].get("max_ram", 0), 2),
                    "max_disk": round(result[0].get("max_disk", 0), 2),
                    "data_points": result[0].get("count", 0)
                }
            return {}
        except Exception as e:
            logger.error(f"Error getting metrics summary: {e}")
            return {}
    
    # ==================== THREATS ====================
    
    def save_threat(self, threat: Dict) -> bool:
        """Save or update threat alert"""
        try:
            doc = {
                "_id": threat.get("id"),
                "type": threat.get("type"),
                "severity": threat.get("severity"),
                "confidence": threat.get("confidence"),
                "description": threat.get("description"),
                "detected_at": datetime.fromisoformat(threat.get("detected_at")) 
                               if threat.get("detected_at") else datetime.utcnow(),
                "status": threat.get("status", "ACTIVE"),
                "auto_action": threat.get("auto_action"),
                "preventive_steps": threat.get("preventive_steps", []),
                "user_message": threat.get("user_message"),
                "icon": threat.get("icon"),
                "color": threat.get("color"),
                "anomaly_score": threat.get("anomaly_score"),
                "raw_data": threat.get("raw_data"),
                "source_ip": threat.get("source_ip"),
                "destination_ip": threat.get("destination_ip"),
                "port": threat.get("port"),
                "protocol": threat.get("protocol")
            }
            
            self.threats.replace_one({"_id": doc["_id"]}, doc, upsert=True)
            return True
        except DuplicateKeyError:
            logger.warning(f"Threat {threat.get('id')} already exists")
            return True  # Not really an error
        except Exception as e:
            logger.error(f"Error saving threat: {e}")
            return False
    
    def get_all_threats(self, limit: int = 100, status: str = None) -> List[Dict]:
        """Get threats with optional status filter"""
        try:
            query = {}
            if status:
                query["status"] = status
            
            threats = list(self.threats.find(query)
                          .sort("detected_at", DESCENDING)
                          .limit(limit))
            
            for t in threats:
                t["_id"] = str(t["_id"])
                if "detected_at" in t:
                    t["detected_at"] = t["detected_at"].isoformat()
            
            return threats
        except Exception as e:
            logger.error(f"Error getting threats: {e}")
            return []
    
    def get_threat_by_id(self, threat_id: str) -> Optional[Dict]:
        """Get single threat by ID"""
        try:
            threat = self.threats.find_one({"_id": threat_id})
            if threat:
                threat["_id"] = str(threat["_id"])
                if "detected_at" in threat:
                    threat["detected_at"] = threat["detected_at"].isoformat()
            return threat
        except Exception as e:
            logger.error(f"Error getting threat: {e}")
            return None
    
    def resolve_threat(self, threat_id: str) -> bool:
        """Mark threat as resolved"""
        try:
            result = self.threats.update_one(
                {"_id": threat_id},
                {"$set": {
                    "status": "RESOLVED", 
                    "resolved_at": datetime.utcnow()
                }}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Error resolving threat: {e}")
            return False
    
    def get_threat_statistics(self) -> Dict:
        """Get threat statistics for dashboard"""
        try:
            pipeline = [
                {"$group": {
                    "_id": "$status",
                    "count": {"$sum": 1}
                }}
            ]
            
            result = list(self.threats.aggregate(pipeline))
            stats = {"ACTIVE": 0, "RESOLVED": 0}
            
            for r in result:
                stats[r["_id"]] = r["count"]
            
            # Get threats by type
            type_pipeline = [
                {"$group": {
                    "_id": "$type",
                    "count": {"$sum": 1}
                }},
                {"$sort": {"count": DESCENDING}},
                {"$limit": 10}
            ]
            
            type_stats = list(self.threats.aggregate(type_pipeline))
            
            return {
                "by_status": stats,
                "by_type": {t["_id"]: t["count"] for t in type_stats},
                "total": sum(stats.values())
            }
        except Exception as e:
            logger.error(f"Error getting threat statistics: {e}")
            return {}
    
    # ==================== PROCESSES ====================
    
    def save_process(self, process: Dict) -> bool:
        """Save process snapshot"""
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "pid": process.get("pid"),
                "name": process.get("name"),
                "cpu_percent": process.get("cpu_percent"),
                "memory_percent": process.get("memory_percent"),
                "risk_score": process.get("risk_score"),
                "is_known": process.get("is_known"),
                "exe_path": process.get("exe_path"),
                "status": process.get("status", "RUNNING")
            }
            self.processes.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving process: {e}")
            return False
    
    def get_recent_processes(self, limit: int = 100) -> List[Dict]:
        """Get recent process snapshots"""
        try:
            processes = list(self.processes.find()
                            .sort("timestamp", DESCENDING)
                            .limit(limit))
            
            for p in processes:
                p["_id"] = str(p["_id"])
                if "timestamp" in p:
                    p["timestamp"] = p["timestamp"].isoformat()
            
            return processes
        except Exception as e:
            logger.error(f"Error getting processes: {e}")
            return []
    
    # ==================== NETWORK EVENTS ====================
    
    def save_network_event(self, event: Dict) -> bool:
        """Save network connection event"""
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "local_ip": event.get("local_ip"),
                "local_port": event.get("local_port"),
                "remote_ip": event.get("remote_ip"),
                "remote_port": event.get("remote_port"),
                "status": event.get("status"),
                "pid": event.get("pid"),
                "is_suspicious": event.get("is_suspicious", False)
            }
            self.network_events.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving network event: {e}")
            return False
    
    def get_suspicious_network_events(self, limit: int = 50) -> List[Dict]:
        """Get suspicious network events"""
        try:
            events = list(self.network_events.find({"is_suspicious": True})
                         .sort("timestamp", DESCENDING)
                         .limit(limit))
            
            for e in events:
                e["_id"] = str(e["_id"])
                if "timestamp" in e:
                    e["timestamp"] = e["timestamp"].isoformat()
            
            return events
        except Exception as e:
            logger.error(f"Error getting network events: {e}")
            return []
    
    # ==================== PACKET EVENTS ====================
    
    def save_packet_event(self, packet_info: Dict) -> bool:
        """Save packet capture event"""
        try:
            doc = {
                "timestamp": datetime.utcnow(),
                "protocol": packet_info.get("protocol"),
                "src_ip": packet_info.get("src_ip"),
                "dst_ip": packet_info.get("dst_ip"),
                "src_port": packet_info.get("src_port"),
                "dst_port": packet_info.get("dst_port"),
                "length": packet_info.get("length"),
                "flags": packet_info.get("flags"),
                "payload_preview": packet_info.get("payload_preview"),
                "is_suspicious": packet_info.get("is_suspicious", False),
                "threat_type": packet_info.get("threat_type"),
                "confidence": packet_info.get("confidence")
            }
            self.packet_events.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving packet event: {e}")
            return False
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get recent packet events"""
        try:
            packets = list(self.packet_events.find()
                          .sort("timestamp", DESCENDING)
                          .limit(limit))
            
            for p in packets:
                p["_id"] = str(p["_id"])
                if "timestamp" in p:
                    p["timestamp"] = p["timestamp"].isoformat()
            
            return packets
        except Exception as e:
            logger.error(f"Error getting packets: {e}")
            return []
    
    def get_suspicious_packets(self, limit: int = 50) -> List[Dict]:
        """Get suspicious packet events"""
        try:
            packets = list(self.packet_events.find({"is_suspicious": True})
                          .sort("timestamp", DESCENDING)
                          .limit(limit))
            
            for p in packets:
                p["_id"] = str(p["_id"])
                if "timestamp" in p:
                    p["timestamp"] = p["timestamp"].isoformat()
            
            return packets
        except Exception as e:
            logger.error(f"Error getting suspicious packets: {e}")
            return []
    
    def get_packet_statistics(self) -> Dict:
        """Get packet capture statistics"""
        try:
            # Total packets
            total = self.packet_events.count_documents({})
            
            # Suspicious count
            suspicious = self.packet_events.count_documents({"is_suspicious": True})
            
            # By threat type
            pipeline = [
                {"$match": {"is_suspicious": True, "threat_type": {"$ne": None}}},
                {"$group": {
                    "_id": "$threat_type",
                    "count": {"$sum": 1}
                }},
                {"$sort": {"count": DESCENDING}}
            ]
            
            by_type = list(self.packet_events.aggregate(pipeline))
            
            # By protocol
            proto_pipeline = [
                {"$group": {
                    "_id": "$protocol",
                    "count": {"$sum": 1}
                }},
                {"$sort": {"count": DESCENDING}}
            ]
            
            by_protocol = list(self.packet_events.aggregate(proto_pipeline))
            
            return {
                "total": total,
                "suspicious": suspicious,
                "by_type": {t["_id"]: t["count"] for t in by_type},
                "by_protocol": {p["_id"]: p["count"] for p in by_protocol}
            }
        except Exception as e:
            logger.error(f"Error getting packet statistics: {e}")
            return {}
    
    # ==================== ALERTS ====================
    
    def save_alert(self, alert: Dict) -> bool:
        """Save alert notification"""
        try:
            doc = {
                "threat_id": alert.get("threat_id"),
                "message": alert.get("message"),
                "sent_at": datetime.utcnow(),
                "channel": alert.get("channel"),
                "status": alert.get("status", "SENT")
            }
            self.alerts.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
            return False
    
    # ==================== AUTO RESPONSE ====================
    
    def save_auto_response(self, threat_id: str, action: str, 
                          success: bool, message: str, 
                          rollback: str = None) -> bool:
        """Log auto-response action"""
        try:
            doc = {
                "threat_id": threat_id,
                "action": action,
                "success": success,
                "message": message,
                "rollback_instructions": rollback,
                "executed_at": datetime.utcnow()
            }
            self.auto_response.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving auto-response: {e}")
            return False
    
    def get_auto_response_history(self, threat_id: str = None, 
                                  limit: int = 50) -> List[Dict]:
        """Get auto-response history"""
        try:
            query = {}
            if threat_id:
                query["threat_id"] = threat_id
            
            responses = list(self.auto_response.find(query)
                            .sort("executed_at", DESCENDING)
                            .limit(limit))
            
            for r in responses:
                r["_id"] = str(r["_id"])
                if "executed_at" in r:
                    r["executed_at"] = r["executed_at"].isoformat()
            
            return responses
        except Exception as e:
            logger.error(f"Error getting auto-response history: {e}")
            return []
    
    # ==================== QUARANTINE ====================
    
    def save_quarantine(self, file_path: str, original_path: str, 
                       threat_type: str, file_hash: str, 
                       file_size: int) -> bool:
        """Save quarantine record"""
        try:
            doc = {
                "file_path": file_path,
                "original_path": original_path,
                "threat_type": threat_type,
                "file_hash": file_hash,
                "file_size": file_size,
                "quarantined_at": datetime.utcnow()
            }
            self.quarantine.insert_one(doc)
            return True
        except Exception as e:
            logger.error(f"Error saving quarantine: {e}")
            return False
    
    def get_quarantine_list(self, limit: int = 50) -> List[Dict]:
        """Get quarantined files list"""
        try:
            items = list(self.quarantine.find()
                        .sort("quarantined_at", DESCENDING)
                        .limit(limit))
            
            for i in items:
                i["_id"] = str(i["_id"])
                if "quarantined_at" in i:
                    i["quarantined_at"] = i["quarantined_at"].isoformat()
            
            return items
        except Exception as e:
            logger.error(f"Error getting quarantine list: {e}")
            return []
    
    # ==================== UTILITY ====================
    
    def get_collection_stats(self) -> Dict:
        """Get statistics for all collections"""
        try:
            stats = {}
            for collection_name in self.db.list_collection_names():
                collection = self.db[collection_name]
                stats[collection_name] = collection.count_documents({})
            return stats
        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {}
    
    def clear_old_data(self, days: int = 30) -> int:
        """Clear data older than specified days"""
        try:
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            deleted = 0
            for collection in [self.metrics, self.network_events, 
                             self.packet_events, self.processes]:
                result = collection.delete_many({"timestamp": {"$lt": cutoff}})
                deleted += result.deleted_count
            
            logger.info(f"Cleared {deleted} records older than {days} days")
            return deleted
        except Exception as e:
            logger.error(f"Error clearing old data: {e}")
            return 0
    
    def close(self):
        """Close MongoDB connection"""
        try:
            self.client.close()
            logger.info("MongoDB connection closed")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")


# ==================== GLOBAL INSTANCE ====================

_mongo_instance: Optional[MongoDBManager] = None


def get_mongo(connection_string: str = None, 
              db_name: str = "sentinel") -> MongoDBManager:
    """
    Get or create MongoDB singleton instance.
    
    Args:
        connection_string: Optional override for connection string
        db_name: Database name
    
    Returns:
        MongoDBManager instance
    """
    global _mongo_instance
    
    if _mongo_instance is None:
        conn_string = connection_string or "mongodb://localhost:27017/"
        _mongo_instance = MongoDBManager(conn_string, db_name)
    
    return _mongo_instance


def close_mongo():
    """Close MongoDB connection"""
    global _mongo_instance
    if _mongo_instance:
        _mongo_instance.close()
        _mongo_instance = None


# ==================== CLI TEST ====================

if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    print("=" * 50)
    print("SENTINEL MongoDB Manager Test")
    print("=" * 50)
    
    # Use command line arg or default
    conn_string = sys.argv[1] if len(sys.argv) > 1 else "mongodb://localhost:27017/"
    
    try:
        mongo = get_mongo(conn_string)
        
        print("\n[OK] MongoDB connected!")
        print(f"Database: {mongo.db_name}")
        
        # Test save
        test_threat = {
            "id": f"test_{datetime.utcnow().timestamp()}",
            "type": "TEST_THREAT",
            "severity": "LOW",
            "confidence": 50,
            "description": "Test threat for MongoDB validation",
            "status": "ACTIVE"
        }
        
        if mongo.save_threat(test_threat):
            print("\n[OK] Threat saved successfully!")
        
        # Test get
        threats = mongo.get_all_threats(limit=5)
        print(f"\n[*] Retrieved {len(threats)} threats")
        
        # Test stats
        stats = mongo.get_collection_stats()
        print(f"\n[*] Collection stats: {stats}")
        
        # Cleanup test
        mongo.threats.delete_one({"_id": test_threat["id"]})
        print("[OK] Test threat cleaned up")
        
        print("\n" + "=" * 50)
        print("MongoDB test completed successfully!")
        print("=" * 50)
        
    except Exception as e:
        print(f"\n[ERROR] MongoDB test failed: {e}")
        print("\nMake sure MongoDB is running:")
        print("  Local: mongod --dbpath /path/to/data")
        print("  Atlas: Use your connection string")
        sys.exit(1)
