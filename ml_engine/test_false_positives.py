"""
Test script to verify false positive scenarios reported by the user.
Ensures that legitimate processes and normal network activity are not flagged as threats.
"""

import sys
import os
import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml_engine.detector import SentinelDetector

def create_false_positive_snapshot() -> dict:
    """Create a system snapshot simulating normal but heavy usage."""
    return {
        "system": {
            "cpu_percent": 35.0,
            "ram_percent": 55.0,
            "disk_percent": 20.0,
            "battery_percent": 100.0,
            "hostname": "DEV-MACHINE",
            "os": "Windows",
            "timestamp": datetime.datetime.utcnow().isoformat()
        },
        "processes": [
            {
                "pid": 1001,
                "name": "vmware-usbarbitrator64.exe",
                "cpu_percent": 0.1,
                "memory_percent": 1.5,
                "status": "running",
                "exe_path": "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmware-usbarbitrator64.exe",
                "username": "SYSTEM",
                "risk_score": 0, # Should be 0 because it's in KNOWN_SAFE
                "is_known": True,
                "command_line": "vmware-usbarbitrator64.exe"
            },
            {
                "pid": 1002,
                "name": "smartscreen.exe",
                "cpu_percent": 0.5,
                "memory_percent": 2.0,
                "status": "running",
                "exe_path": "C:\\Windows\\System32\\smartscreen.exe",
                "username": "user",
                "risk_score": 0,
                "is_known": True,
                "command_line": "smartscreen.exe -Embedding"
            },
            {
                "pid": 1003,
                "name": "chrome.exe",
                "cpu_percent": 15.0,
                "memory_percent": 45.0, # High memory browser
                "status": "running",
                "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "username": "user",
                "risk_score": 5,
                "is_known": True,
                "command_line": "chrome.exe --type=renderer"
            }
        ],
        "network": {
            # Simulate 50 normal web connections (previously triggered MITM alert)
            "connections": [
                {
                    "local_ip": "192.168.1.100",
                    "local_port": 50000 + i,
                    "remote_ip": f"104.21.5.{i}", 
                    "remote_port": 443,
                    "status": "ESTABLISHED",
                    "pid": 1003,
                    "is_suspicious": False,
                    "reason": []
                } for i in range(50)
            ],
            # Simulate 2GB of downloaded data (previously triggered DDoS alert)
            "bytes_sent": 500_000_000,
            "bytes_recv": 2_000_000_000, 
            "packets_sent": 500_000,
            "packets_recv": 2_000_000,
            "suspicious_connections": [],
            "timestamp": datetime.datetime.utcnow().isoformat()
        },
        "security": {
            "startup_items": [],
            "usb_devices": [],
            "open_ports": [80, 443],
            "events": [],
            "timestamp": datetime.datetime.utcnow().isoformat()
        },
        "snapshot_time": datetime.datetime.utcnow().isoformat()
    }

def run_false_positive_test():
    print("\n" + "="*70)
    print("TEST: False Positive Prevention")
    print("="*70)
    
    detector = SentinelDetector()
    snapshot = create_false_positive_snapshot()
    
    # 1. Verify risk scoring for known processes
    from agent.collector import ProcessCollector
    collector = ProcessCollector()
    
    vmware_score = collector._calculate_risk(snapshot["processes"][0])
    smartscreen_score = collector._calculate_risk(snapshot["processes"][1])
    
    print(f"Risk Score for vmware-usbarbitrator64: {vmware_score}")
    print(f"Risk Score for smartscreen: {smartscreen_score}")
    
    if vmware_score > 20 or smartscreen_score > 20:
        print("FAIL: Known processes still getting high risk scores.")
        return False
        
    # 2. Verify detector analysis
    result = detector.analyze(snapshot)
    threats = result.get("threats", [])
    
    if len(threats) > 0:
        print(f"FAIL: Detected {len(threats)} false positive threats:")
        for t in threats:
            print(f"  - {t['type']}: {t['description']}")
        return False
        
    print("PASS: System correctly ignored VMware, SmartScreen, and normal heavy network usage.")
    return True

if __name__ == "__main__":
    success = run_false_positive_test()
    sys.exit(0 if success else 1)
