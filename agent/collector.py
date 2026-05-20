"""
SENTINEL - 24x7 PC Monitoring Agent
Collects system metrics every 5 seconds
"""

import psutil
import platform
import socket
import time
import json
import datetime
import os
import hashlib
import threading
from pathlib import Path

try:
    from database.db_manager import save_packet_event
except ImportError:
    # Handle direct execution
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(__file__)))
    from database.db_manager import save_packet_event

try:
    from .packet_capture import PacketCapture, PacketCaptureManager
    PACKET_CAPTURE_AVAILABLE = True
except ImportError:
    PACKET_CAPTURE_AVAILABLE = False

class SystemCollector:
    """Collects CPU, RAM, Disk, Battery metrics"""

    def collect(self):
        cpu = psutil.cpu_percent(interval=1)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        battery = psutil.sensors_battery()
        temps = {}

        try:
            sensor_data = psutil.sensors_temperatures()
            if sensor_data:
                for name, entries in sensor_data.items():
                    if entries:
                        temps[name] = entries[0].current
        except Exception:
            pass

        return {
            "cpu_percent": cpu,
            "cpu_count": psutil.cpu_count(),
            "ram_total": ram.total,
            "ram_used": ram.used,
            "ram_percent": ram.percent,
            "disk_total": disk.total,
            "disk_used": disk.used,
            "disk_percent": disk.percent,
            "battery_percent": battery.percent if battery else None,
            "battery_charging": battery.power_plugged if battery else None,
            "temperatures": temps,
            "os": platform.system(),
            "hostname": socket.gethostname(),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


class ProcessCollector:
    """Collects all running processes with risk scoring"""

    KNOWN_SAFE = {
        "chrome.exe", "firefox.exe", "explorer.exe", "svchost.exe",
        "python.exe", "code.exe", "notepad.exe", "taskmgr.exe",
        "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "dwm.exe",
        "spoolsv.exe", "searchindexer.exe", "node.exe", "cmd.exe",
        "powershell.exe", "conhost.exe", "runtimebroker.exe",
        "microsoft.store.exe", "winstore.app.exe", "applicationframehost.exe",
        "shellexperiencehost.exe", "startmenuexperiencehost.exe",
        "smartscreen.exe", "vmware-usbarbitrator64.exe", "vmware-authd.exe", 
        "vmnat.exe", "vmnetdhcp.exe", "fontdrvhost.exe", "ctfmon.exe", 
        "compattelrunner.exe", "sihost.exe", "securityhealthservice.exe", 
        "msmpeng.exe", "nissrv.exe", "dashhost.exe"
    }

    SUSPICIOUS_NAMES = [
        "miner", "crypto", "keylog", "-rat", "trojan", "backdoor",
        "rootkit", "spyware", "ransom", "crypt", "hack", "steal",
        "stealer"
    ]

    def collect(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent',
                                          'memory_percent', 'status',
                                          'create_time', 'exe', 'username']):
            try:
                info = proc.info
                risk_score = self._calculate_risk(info)
                processes.append({
                    "pid": info['pid'],
                    "name": info['name'] or "unknown",
                    "cpu_percent": info['cpu_percent'] or 0,
                    "memory_percent": round(info['memory_percent'] or 0, 2),
                    "status": info['status'],
                    "exe_path": info['exe'] or "unknown",
                    "username": info['username'] or "unknown",
                    "risk_score": risk_score,
                    "is_known": (info['name'] or "").lower() in self.KNOWN_SAFE,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def _calculate_risk(self, proc_info):
        score = 0
        name = (proc_info.get('name') or "").lower()
        exe = (proc_info.get('exe') or "").lower()
        cpu = proc_info.get('cpu_percent') or 0
        mem = proc_info.get('memory_percent') or 0

        # Unknown process penalty
        if name not in [p.lower() for p in self.KNOWN_SAFE]:
            score += 20

        # Suspicious name keywords
        import re
        for keyword in self.SUSPICIOUS_NAMES:
            if keyword.startswith('-'):
                # Exact word matching for short, generic names
                pattern = r'\b' + re.escape(keyword[1:]) + r'\b'
                if re.search(pattern, name) or re.search(pattern, exe):
                    score += 40
            else:
                # Substring matching
                if keyword in name or keyword in exe:
                    score += 40

        # High resource usage
        if cpu > 80:
            score += 25
        elif cpu > 50:
            score += 10

        if mem > 50:
            score += 15

        # Running from temp/unusual locations
        suspicious_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                            "/tmp/", "/var/tmp/"]
        for path in suspicious_paths:
            if path in exe:
                score += 30

        return min(score, 100)


class NetworkCollector:
    """Collects network connections and bandwidth"""

    SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999,
                        1337, 31337, 12345, 54321]

    def collect(self):
        connections = []
        net_io = psutil.net_io_counters()

        for conn in psutil.net_connections(kind='inet'):
            try:
                is_suspicious = False
                reason = []

                if conn.laddr and conn.laddr.port in self.SUSPICIOUS_PORTS:
                    is_suspicious = True
                    reason.append("suspicious_port")

                if conn.raddr:
                    if conn.raddr.port in self.SUSPICIOUS_PORTS:
                        is_suspicious = True
                        reason.append("suspicious_remote_port")

                connections.append({
                    "local_ip": conn.laddr.ip if conn.laddr else None,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "remote_ip": conn.raddr.ip if conn.raddr else None,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                    "is_suspicious": is_suspicious,
                    "reason": reason,
                    "timestamp": datetime.datetime.utcnow().isoformat()
                })
            except Exception:
                continue

        return {
            "connections": connections,
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv,
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
            "suspicious_connections": [c for c in connections if c['is_suspicious']],
            "timestamp": datetime.datetime.utcnow().isoformat()
        }


class SecurityCollector:
    """Collects security-related events"""

    def collect(self):
        startup_items = self._get_startup_items()
        usb_devices = self._get_usb_devices()

        return {
            "startup_items": startup_items,
            "usb_devices": usb_devices,
            "open_ports": self._get_open_ports(),
            "timestamp": datetime.datetime.utcnow().isoformat()
        }

    def _get_startup_items(self):
        items = []
        # Windows registry startup (simplified)
        startup_paths = []
        if platform.system() == "Windows":
            startup_paths = [
                os.path.expanduser("~\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            ]
        elif platform.system() == "Linux":
            startup_paths = ["/etc/init.d/", "/etc/rc.local"]

        for path in startup_paths:
            if os.path.exists(path):
                try:
                    if os.path.isdir(path):
                        for f in os.listdir(path):
                            items.append({"name": f, "path": os.path.join(path, f)})
                except Exception:
                    pass
        return items

    def _get_usb_devices(self):
        devices = []
        try:
            partitions = psutil.disk_partitions()
            for p in partitions:
                if 'removable' in p.opts or 'cdrom' in p.opts:
                    devices.append({
                        "device": p.device,
                        "mountpoint": p.mountpoint,
                        "fstype": p.fstype
                    })
        except Exception:
            pass
        return devices

    def _get_open_ports(self):
        ports = []
        try:
            for conn in psutil.net_connections():
                if conn.status == 'LISTEN' and conn.laddr:
                    ports.append(conn.laddr.port)
        except Exception:
            pass
        return list(set(ports))


class SentinelAgent:
    """Main agent that orchestrates all collectors"""

    def __init__(self, enable_packet_capture=False, packet_config=None):
        self.system = SystemCollector()
        self.process = ProcessCollector()
        self.network = NetworkCollector()
        self.security = SecurityCollector()
        
        # Packet capture (optional)
        self.packet_capture = None
        self.packet_capture_enabled = enable_packet_capture
        
        if enable_packet_capture and PACKET_CAPTURE_AVAILABLE:
            config = packet_config or {}
            self.packet_capture = PacketCapture(
                interface=config.get('interface'),
                sample_rate=config.get('sample_rate', 0.5),
                lightweight_mode=config.get('lightweight_mode', False)
            )
    
    def start_packet_monitoring(self):
        """Start background packet capture"""
        if self.packet_capture and PACKET_CAPTURE_AVAILABLE:
            return self.packet_capture.start()
        return False
    
    def stop_packet_monitoring(self):
        """Stop packet capture"""
        if self.packet_capture and PACKET_CAPTURE_AVAILABLE:
            self.packet_capture.stop()
    
    def get_packet_data(self):
        """Get recent packet analysis data"""
        if self.packet_capture and PACKET_CAPTURE_AVAILABLE:
            return {
                'recent_packets': self.packet_capture.get_recent_packets(limit=50),
                'suspicious_packets': self.packet_capture.get_suspicious_packets(limit=20),
                'statistics': self.packet_capture.get_statistics(),
                'protocol_distribution': self.packet_capture.get_protocol_distribution(),
                'threat_summary': self.packet_capture.get_threat_summary()
            }
        return None
    
    def collect_all(self):
        """Collect all metrics in one snapshot"""
        data = {
            "system": self.system.collect(),
            "processes": self.process.collect(),
            "network": self.network.collect(),
            "security": self.security.collect(),
            "snapshot_time": datetime.datetime.utcnow().isoformat()
        }
        
        # Add packet data if available
        if self.packet_capture and PACKET_CAPTURE_AVAILABLE:
            packet_data = self.get_packet_data()
            data["packets"] = packet_data
            
            # Persist captured packets to the database
            if packet_data and 'recent_packets' in packet_data:
                for packet in packet_data['recent_packets']:
                    save_packet_event(packet)
        
        return data


if __name__ == "__main__":
    agent = SentinelAgent()
    print("[SENTINEL] Agent Started")
    print("Collecting system data...\n")
    data = agent.collect_all()
    print(f"[OK] CPU: {data['system']['cpu_percent']}%")
    print(f"[OK] RAM: {data['system']['ram_percent']}%")
    print(f"[OK] Disk: {data['system']['disk_percent']}%")
    print(f"[OK] Processes found: {len(data['processes'])}")
    print(f"[OK] Network connections: {len(data['network']['connections'])}")
    print(f"[OK] Suspicious connections: {len(data['network']['suspicious_connections'])}")
