"""
SENTINEL - Packet Capture Module
================================
Live packet inspection using scapy for network-level threat detection.
Captures and analyzes packets in real-time for security monitoring.

Features:
- Live packet capture with configurable sampling
- Protocol analysis (TCP, UDP, ICMP, DNS, HTTP)
- Suspicious pattern detection
- PCAP export for forensics
- Lightweight mode for minimal overhead
"""

import threading
import datetime
import json
import os
import logging
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import time

try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR,
        Ether, ARP, Raw, conf, get_if_list
    )
    SCAPY_AVAILABLE = True
    conf.verb = 0  # Disable scapy verbose output
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger('SENTINEL.PacketCapture')


@dataclass
class PacketInfo:
    """Standardized packet information structure"""
    timestamp: str
    protocol: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    flags: Optional[str] = None
    payload_preview: Optional[str] = None
    is_suspicious: bool = False
    threat_type: Optional[str] = None
    confidence: int = 0
    
    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


class PacketAnalyzer:
    """Analyzes captured packets for security threats"""
    
    # Suspicious ports commonly used by malware
    SUSPICIOUS_PORTS = {
        4444: "Metasploit default",
        5555: "Android debug bridge (potential backdoor)",
        6666: "IRC (common botnet port)",
        6667: "IRC (common botnet port)",
        7777: "Common backdoor port",
        8888: "Common backdoor port",
        9999: "Common backdoor port",
        1337: "Leet port (common in exploits)",
        31337: "Back Orifice (elite)",
        12345: "NetBus trojan",
        54321: "SchoolBus trojan",
        23: "Telnet (unencrypted)",
        445: "SMB (common attack vector)",
        135: "RPC (common attack vector)",
        139: "NetBIOS (common attack vector)",
        3389: "RDP (brute force target)",
        22: "SSH (brute force target)",
        21: "FTP (unencrypted)",
        1433: "MSSQL (common attack target)",
        3306: "MySQL (common attack target)",
        5900: "VNC (remote access)",
    }
    
    # Known C2 beacon intervals (in seconds)
    C2_BEACON_INTERVALS = [30, 60, 120, 300, 600, 900, 1800, 3600]
    
    def __init__(self):
        self.connection_history = defaultdict(list)  # dst_ip -> [timestamps]
        self.dns_queries = defaultdict(int)  # domain -> count
        self.port_scan_tracker = defaultdict(set)  # src_ip -> set of ports
        self.last_analysis_time = defaultdict(float)  # src_ip -> last_timestamp
        self.last_alert_time = defaultdict(float)  # src_ip -> last_alert_timestamp
        self.alert_cooldown = 30.0  # seconds between alerts per IP
        self.alert_cooldown_dns = 60.0  # cooldown for DNS alerts
        self.alert_cooldown_icmp = 60.0  # cooldown for ICMP alerts
        self.alert_cooldown_beacon = 300.0  # cooldown for C2 beacon alerts (5 min)
        
    def analyze_packet(self, packet) -> Optional[PacketInfo]:
        """Analyze a single packet for threats"""
        if not SCAPY_AVAILABLE:
            return None
            
        try:
            packet_info = self._extract_packet_info(packet)
            if not packet_info:
                return None
                
            # Run threat detection
            threat_analysis = self._detect_threats(packet, packet_info)
            packet_info.is_suspicious = threat_analysis['is_suspicious']
            packet_info.threat_type = threat_analysis['threat_type']
            packet_info.confidence = threat_analysis['confidence']
            
            return packet_info
            
        except Exception as e:
            logger.debug(f"Error analyzing packet: {e}")
            return None
    
    def _extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """Extract standardized information from packet"""
        try:
            # Determine the actual network protocol by checking packet layers
            # Check from innermost (payload) to outermost layer for actual protocol
            protocol = "UNKNOWN"

            # Check for application layer protocols first
            if DNS in packet:
                protocol = "DNS"
            elif TCP in packet:
                # Check for HTTP/HTTPS by port or payload content
                dst_port = packet[TCP].dport if TCP in packet else None
                src_port = packet[TCP].sport if TCP in packet else None
                
                # Check payload for HTTP methods
                is_http = False
                is_https = False
                
                if Raw in packet:
                    try:
                        payload = bytes(packet[Raw].load)
                        payload_str = payload.decode('utf-8', errors='ignore')[:20]
                        # HTTP methods detection
                        if any(method in payload_str for method in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'HTTP/']):
                            is_http = True
                    except:
                        pass
                
                # Port-based detection (fallback)
                if not is_http:
                    if dst_port in [80, 8080] or src_port in [80, 8080]:
                        is_http = True
                    elif dst_port == 443 or src_port == 443:
                        is_https = True
                
                if is_http:
                    protocol = "HTTP"
                elif is_https:
                    protocol = "HTTPS"
                else:
                    protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            elif ARP in packet:
                protocol = "ARP"
            elif IP in packet:
                protocol = "IP"
            else:
                # Fallback: get the last layer name (actual payload protocol)
                # This avoids showing "Ether" or "loopback" from outer layers
                protocol = packet.name
                # Clean up protocol name
                if protocol in ['Ether', 'loopback', 'Loopback', 'Dot1Q', 'LLC']:
                    protocol = "OTHER"

            src_ip = packet[IP].src if IP in packet else None
            dst_ip = packet[IP].dst if IP in packet else None

            src_port = packet[TCP].sport if TCP in packet else (
                packet[UDP].sport if UDP in packet else None
            )
            dst_port = packet[TCP].dport if TCP in packet else (
                packet[UDP].dport if UDP in packet else None
            )

            # Extract flags for TCP
            flags = None
            if TCP in packet:
                flags = str(packet[TCP].flags)

            # Extract payload preview
            payload_preview = None
            if Raw in packet:
                try:
                    payload = bytes(packet[Raw].load)
                    payload_preview = payload[:50].decode('utf-8', errors='ignore')
                except:
                    pass

            # Extract DNS query if present
            if DNS in packet and DNSQR in packet:
                try:
                    qname = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                    if payload_preview is None:
                        payload_preview = f"DNS Query: {qname}"
                except:
                    pass

            packet_length = len(packet)

            return PacketInfo(
                timestamp=datetime.datetime.now().isoformat(),
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                length=packet_length,
                flags=flags,
                payload_preview=payload_preview[:100] if payload_preview else None
            )

        except Exception as e:
            logger.debug(f"Error extracting packet info: {e}")
            return None
    
    def _detect_threats(self, packet, packet_info: PacketInfo) -> Dict:
        """Detect threats in packet"""
        current_time = time.time()
        result = {
            'is_suspicious': False,
            'threat_type': None,
            'confidence': 0
        }

        # 1. Port Scan Detection
        if packet_info.src_ip and packet_info.dst_port:
            self.port_scan_tracker[packet_info.src_ip].add(packet_info.dst_port)

            # Check if many ports scanned in short time
            if current_time - self.last_analysis_time.get(packet_info.src_ip, 0) < 10:
                port_count = len(self.port_scan_tracker[packet_info.src_ip])
                # Increased threshold from 10 to 25 ports to reduce false positives
                if port_count > 25:
                    # Rate limiting: only alert once per cooldown period per IP
                    if current_time - self.last_alert_time.get(packet_info.src_ip, 0) >= self.alert_cooldown:
                        result['is_suspicious'] = True
                        result['threat_type'] = 'PORT_SCAN_DETECTED'
                        result['confidence'] = min(95, 65 + port_count)
                        self.last_alert_time[packet_info.src_ip] = current_time
                        logger.warning(
                            f"Port scan detected from {packet_info.src_ip}: "
                            f"{port_count} unique ports in 10s window"
                        )
            else:
                # Reset tracker after 10 seconds of inactivity
                self.port_scan_tracker[packet_info.src_ip] = set()

            self.last_analysis_time[packet_info.src_ip] = current_time
        
        # 2. Suspicious Port Detection
        if packet_info.dst_port in self.SUSPICIOUS_PORTS:
            result['is_suspicious'] = True
            result['threat_type'] = f'SUSPICIOUS_PORT_{packet_info.dst_port}'
            result['confidence'] = 75
            # Rate limit suspicious port alerts
            alert_key = f"port_{packet_info.dst_port}"
            if current_time - self.last_alert_time.get(alert_key, 0) >= self.alert_cooldown:
                self.last_alert_time[alert_key] = current_time
                logger.warning(f"Suspicious port detected: {packet_info.dst_port} - {self.SUSPICIOUS_PORTS[packet_info.dst_port]}")

        # 3. DNS Tunneling Detection (large DNS queries)
        if DNS in packet and packet_info.length > 512:
            result['is_suspicious'] = True
            result['threat_type'] = 'POSSIBLE_DNS_TUNNELING'
            result['confidence'] = 80
            # Rate limit DNS tunneling alerts
            if current_time - self.last_alert_time.get("dns_tunnel", 0) >= self.alert_cooldown_dns:
                self.last_alert_time["dns_tunnel"] = current_time
                logger.warning(f"Large DNS query detected: {packet_info.length} bytes (possible DNS tunneling)")

        # 4. ICMP Tunneling Detection (oversized ICMP)
        if ICMP in packet and packet_info.length > 1000:
            result['is_suspicious'] = True
            result['threat_type'] = 'POSSIBLE_ICMP_TUNNELING'
            result['confidence'] = 75
            # Rate limit ICMP tunneling alerts
            if current_time - self.last_alert_time.get("icmp_tunnel", 0) >= self.alert_cooldown_icmp:
                self.last_alert_time["icmp_tunnel"] = current_time
                logger.warning(f"Oversized ICMP packet: {packet_info.length} bytes (possible ICMP tunneling)")
        
        # 5. C2 Beaconing Detection
        if packet_info.dst_ip:
            current_time = time.time()
            self.connection_history[packet_info.dst_ip].append(current_time)

            # Keep only last 10 connections
            if len(self.connection_history[packet_info.dst_ip]) > 10:
                self.connection_history[packet_info.dst_ip] = self.connection_history[packet_info.dst_ip][-10:]

            # Check for regular intervals
            if len(self.connection_history[packet_info.dst_ip]) >= 5:
                intervals = []
                timestamps = sorted(self.connection_history[packet_info.dst_ip])
                for i in range(1, len(timestamps)):
                    intervals.append(timestamps[i] - timestamps[i-1])

                # Check if intervals are consistent (beaconing)
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)

                    # Low variance = regular intervals (possible beaconing)
                    if variance < 5 and avg_interval in range(25, 3605):  # 25s to 1 hour
                        for beacon_interval in self.C2_BEACON_INTERVALS:
                            if abs(avg_interval - beacon_interval) < 5:
                                result['is_suspicious'] = True
                                result['threat_type'] = 'POSSIBLE_C2_BEACONING'
                                result['confidence'] = 85
                                # Rate limit C2 beacon alerts (5 min cooldown per destination IP)
                                beacon_alert_key = f"beacon_{packet_info.dst_ip}"
                                if current_time - self.last_alert_time.get(beacon_alert_key, 0) >= self.alert_cooldown_beacon:
                                    self.last_alert_time[beacon_alert_key] = current_time
                                    logger.warning(
                                        f"C2 beaconing detected to {packet_info.dst_ip} "
                                        f"every {avg_interval:.0f}s (variance: {variance:.2f})"
                                    )
                                break
        
        # 6. ARP Spoofing Detection
        if ARP in packet:
            if packet[ARP].op == 2:  # ARP reply
                # In a real implementation, you'd track MAC-IP mappings
                # and detect changes
                pass
        
        # 7. SYN Flood Detection (basic DDoS)
        if TCP in packet and packet_info.flags:
            if 'S' in str(packet_info.flags) and packet_info.dst_port:
                # Track SYN packets per destination
                pass
        
        return result


class PacketCapture:
    """
    Live packet capture engine using scapy.
    Runs in background thread for non-blocking operation.
    """
    
    def __init__(self, 
                 interface: Optional[str] = None,
                 sample_rate: float = 1.0,
                 max_packets_buffer: int = 1000,
                 lightweight_mode: bool = False):
        """
        Initialize packet capture.
        
        Args:
            interface: Network interface to capture from (None = all)
            sample_rate: Fraction of packets to capture (1.0 = all, 0.5 = 50%)
            max_packets_buffer: Maximum packets to keep in memory
            lightweight_mode: If True, use minimal filtering for lower CPU
        """
        self.interface = interface
        self.sample_rate = sample_rate
        self.max_packets_buffer = max_packets_buffer
        self.lightweight_mode = lightweight_mode
        
        self.running = False
        self.capture_thread = None
        self.analyzer = PacketAnalyzer()
        
        # Packet storage
        self.packets_buffer = deque(maxlen=max_packets_buffer)
        self.suspicious_packets = deque(maxlen=100)
        self.packet_stats = {
            'total_captured': 0,
            'suspicious_count': 0,
            'protocols': defaultdict(int),
            'start_time': None
        }
        
        # PCAP storage
        self.pcap_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'pcap_captures'
        )
        os.makedirs(self.pcap_dir, exist_ok=True)
        
        logger.info(f"PacketCapture initialized (lightweight={lightweight_mode}, sample_rate={sample_rate})")
    
    def start(self):
        """Start packet capture in background thread"""
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available - packet capture disabled")
            return False
            
        if self.running:
            logger.warning("Packet capture already running")
            return True
        
        self.running = True
        self.packet_stats['start_time'] = datetime.datetime.now().isoformat()
        
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketCapture"
        )
        self.capture_thread.start()
        
        logger.info("Packet capture started")
        return True
    
    def stop(self):
        """Stop packet capture"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Packet capture stopped")
    
    def _capture_loop(self):
        """Main capture loop - runs in background thread"""
        while self.running:
            try:
                # Determine packet count based on sample rate
                if self.lightweight_mode:
                    count = 50  # Capture in small batches
                else:
                    count = 100
                
                # Sniff packets
                packets = sniff(
                    iface=self.interface,
                    count=count,
                    timeout=2.0,
                    store=False,  # Don't store in scapy to save memory
                    prn=self._process_packet
                )
                
            except PermissionError:
                logger.error("Permission denied - run as administrator for packet capture")
                self.running = False
                break
            except Exception as e:
                logger.debug(f"Capture error: {e}")
                time.sleep(1)  # Brief pause on error
    
    def _process_packet(self, packet):
        """Process a single captured packet"""
        if not self.running:
            return
        
        # Apply sampling
        import random
        if self.sample_rate < 1.0 and random.random() > self.sample_rate:
            return
        
        # Analyze packet
        packet_info = self.analyzer.analyze_packet(packet)
        
        if packet_info:
            # Update statistics
            self.packet_stats['total_captured'] += 1
            self.packet_stats['protocols'][packet_info.protocol] += 1
            
            # Store packet
            self.packets_buffer.append(packet_info)
            
            # Store suspicious packets separately
            if packet_info.is_suspicious:
                self.suspicious_packets.append(packet_info)
                self.packet_stats['suspicious_count'] += 1
                logger.warning(f"Suspicious packet: {packet_info.threat_type}")
    
    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        """Get most recent captured packets"""
        packets = list(self.packets_buffer)[-limit:]
        return [p.to_dict() for p in reversed(packets)]
    
    def get_suspicious_packets(self, limit: int = 50) -> List[Dict]:
        """Get suspicious packets"""
        packets = list(self.suspicious_packets)[-limit:]
        return [p.to_dict() for p in reversed(packets)]
    
    def get_statistics(self) -> Dict:
        """Get capture statistics"""
        return {
            'total_captured': self.packet_stats['total_captured'],
            'suspicious_count': self.packet_stats['suspicious_count'],
            'protocols': dict(self.packet_stats['protocols']),
            'start_time': self.packet_stats['start_time'],
            'running': self.running,
            'buffer_size': len(self.packets_buffer),
            'sample_rate': self.sample_rate,
            'lightweight_mode': self.lightweight_mode
        }
    
    def get_protocol_distribution(self) -> Dict:
        """Get protocol distribution percentages"""
        total = sum(self.packet_stats['protocols'].values())
        if total == 0:
            return {}
        
        return {
            proto: round((count / total) * 100, 2)
            for proto, count in self.packet_stats['protocols'].items()
        }
    
    def export_pcap(self, duration_seconds: int = 60, output_file: Optional[str] = None) -> str:
        """
        Capture packets and export to PCAP file.
        
        Args:
            duration_seconds: How long to capture
            output_file: Output file path (auto-generated if None)
        
        Returns:
            Path to created PCAP file
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available")
        
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.pcap_dir, f"sentinel_capture_{timestamp}.pcap")
        
        logger.info(f"Starting PCAP export for {duration_seconds} seconds...")
        
        # Capture packets
        packets = sniff(
            iface=self.interface,
            timeout=duration_seconds,
            store=True
        )
        
        # Write to file
        wrpcap(output_file, packets)
        
        logger.info(f"PCAP saved: {output_file} ({len(packets)} packets)")
        return output_file
    
    def get_threat_summary(self) -> Dict:
        """Get summary of detected threats"""
        threats = defaultdict(int)
        for packet in self.suspicious_packets:
            if packet.threat_type:
                threats[packet.threat_type] += 1
        
        return {
            'threats': dict(threats),
            'total_suspicious': len(self.suspicious_packets),
            'last_threat': self.suspicious_packets[-1].to_dict() if self.suspicious_packets else None
        }


class PacketCaptureManager:
    """
    Singleton manager for packet capture.
    Provides global access to packet capture functionality.
    """
    
    _instance = None
    _capture = None
    
    @classmethod
    def get_instance(cls) -> Optional[PacketCapture]:
        """Get the packet capture instance"""
        if cls._capture is None:
            cls._capture = PacketCapture(
                interface=None,
                sample_rate=0.5,  # Sample 50% of packets by default
                lightweight_mode=False
            )
        return cls._capture
    
    @classmethod
    def start_capture(cls) -> bool:
        """Start packet capture"""
        capture = cls.get_instance()
        if capture:
            return capture.start()
        return False
    
    @classmethod
    def stop_capture(cls):
        """Stop packet capture"""
        if cls._capture:
            cls._capture.stop()
    
    @classmethod
    def get_capture(cls) -> Optional[PacketCapture]:
        """Get the capture instance for direct access"""
        return cls.get_instance()


# Convenience functions for direct use
def start_packet_capture(**kwargs) -> bool:
    """Start packet capture with optional configuration"""
    if PacketCaptureManager._capture is None:
        PacketCaptureManager._capture = PacketCapture(**kwargs)
    return PacketCaptureManager.start_capture()


def stop_packet_capture():
    """Stop packet capture"""
    PacketCaptureManager.stop_capture()


def get_packet_capture() -> Optional[PacketCapture]:
    """Get packet capture instance"""
    return PacketCaptureManager.get_capture()


if __name__ == "__main__":
    # Test packet capture
    logging.basicConfig(level=logging.INFO)
    
    print("[SENTINEL] Packet Capture Test")
    print("=" * 50)
    
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy not available - install with: pip install scapy")
        exit(1)
    
    # Start capture
    capture = PacketCapture(
        sample_rate=1.0,
        lightweight_mode=True
    )
    
    print("[*] Starting packet capture... (Press Ctrl+C to stop)")
    capture.start()
    
    try:
        while True:
            time.sleep(5)
            stats = capture.get_statistics()
            print(f"\n[{datetime.datetime.now().strftime('%H:%M:%S')}] Statistics:")
            print(f"  Total packets: {stats['total_captured']}")
            print(f"  Suspicious: {stats['suspicious_count']}")
            print(f"  Protocols: {stats['protocols']}")
            
            threats = capture.get_threat_summary()
            if threats['threats']:
                print(f"  Threats detected: {threats['threats']}")
                
    except KeyboardInterrupt:
        print("\n[*] Stopping capture...")
        capture.stop()
        print("[OK] Packet capture test completed")
