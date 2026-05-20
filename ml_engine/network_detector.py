"""
SENTINEL - Network Packet Threat Detector
=========================================
Detects network-level threats using packet analysis.
Integrates with main detector for comprehensive threat coverage.

New Threats Detected:
1. PORT_SCAN_DETECTED - Network reconnaissance
2. DNS_TUNNELING - Data exfiltration via DNS
3. ICMP_TUNNELING - Covert channel via ICMP
4. C2_BEACONING - Command & Control communication
5. ARP_SPOOFING - Man-in-the-Middle attack
6. COVERT_CHANNEL - Unusual protocol usage
7. NETWORK_RECONNAISSANCE - Service enumeration
"""

import logging
import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict
import time

logger = logging.getLogger('SENTINEL.NetworkDetector')


@dataclass
class NetworkThreat:
    """Network-level threat alert"""
    type: str
    severity: str
    confidence: int
    description: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    port: Optional[int]
    protocol: Optional[str]
    evidence: List[str]
    auto_action: str
    preventive_steps: List[str]
    detected_at: str
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'confidence': self.confidence,
            'description': self.description,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'port': self.port,
            'protocol': self.protocol,
            'evidence': self.evidence,
            'auto_action': self.auto_action,
            'preventive_steps': self.preventive_steps,
            'detected_at': self.detected_at
        }


class NetworkThreatDetector:
    """
    Detects network-level threats from packet analysis data.
    Works alongside main detector for comprehensive coverage.
    """
    
    # Threat response mappings
    NETWORK_THREAT_RESPONSES = {
        'PORT_SCAN_DETECTED': {
            'severity': 'HIGH',
            'auto_action': 'BLOCK_IP',
            'confidence': 85,
            'description': 'Network port scanning detected - possible reconnaissance attack',
            'preventive_steps': [
                'Block the source IP in firewall immediately',
                'Review firewall rules for exposed ports',
                'Enable port scan detection in firewall',
                'Monitor for follow-up exploitation attempts',
                'Check for successful intrusions on scanned ports',
                'Review logs for authentication attempts',
                'Consider enabling port knocking for sensitive services',
                'Report the attack to network administrator'
            ]
        },
        'DNS_TUNNELING': {
            'severity': 'CRITICAL',
            'auto_action': 'SUSPEND_PROCESS',
            'confidence': 90,
            'description': 'DNS tunneling detected - possible data exfiltration',
            'preventive_steps': [
                'Immediately identify and terminate the process making DNS queries',
                'Block the suspicious domain in DNS/firewall',
                'Review all DNS queries for the past 24 hours',
                'Check for data breaches or unauthorized access',
                'Implement DNS query logging and monitoring',
                'Consider using DNS filtering service',
                'Scan system for malware that uses DNS tunneling',
                'Review network traffic for other exfiltration methods'
            ]
        },
        'ICMP_TUNNELING': {
            'severity': 'HIGH',
            'auto_action': 'BLOCK_IP',
            'confidence': 80,
            'description': 'ICMP tunneling detected - covert communication channel',
            'preventive_steps': [
                'Block ICMP traffic from suspicious sources',
                'Review firewall rules for ICMP traffic',
                'Consider blocking ICMP entirely if not needed',
                'Monitor for other covert channel methods',
                'Check for malware that uses ICMP tunneling',
                'Review network baseline for ICMP usage',
                'Implement ICMP rate limiting',
                'Alert security team for investigation'
            ]
        },
        'C2_BEACONING': {
            'severity': 'CRITICAL',
            'auto_action': 'ISOLATE_AND_ALERT',
            'confidence': 92,
            'description': 'Command & Control beaconing detected - system may be compromised',
            'preventive_steps': [
                'IMMEDIATELY isolate system from network',
                "Do NOT terminate process yet (may trigger dead man's switch)",
                'Capture network traffic for forensics',
                'Identify the C2 server IP/domain',
                'Block C2 infrastructure in firewall',
                'Contact incident response team',
                'Preserve evidence for investigation',
                'Prepare for full system rebuild'
            ]
        },
        'ARP_SPOOFING': {
            'severity': 'HIGH',
            'auto_action': 'ALERT_ONLY',
            'confidence': 88,
            'description': 'ARP spoofing detected - possible MITM attack',
            'preventive_steps': [
                "Identify the attacker's MAC address",
                'Enable Dynamic ARP Inspection (DAI) on switches',
                'Use static ARP entries for critical systems',
                'Implement ARP monitoring tools',
                'Check for unauthorized devices on network',
                'Review network segmentation',
                'Consider using ARP spoofing detection tools',
                'Alert all users on affected network segment'
            ]
        },
        'COVERT_CHANNEL': {
            'severity': 'MEDIUM',
            'auto_action': 'ALERT_ONLY',
            'confidence': 70,
            'description': 'Covert communication channel detected - unusual protocol usage',
            'preventive_steps': [
                'Identify the protocol being abused',
                'Review if the traffic is legitimate',
                'Block unnecessary protocols at firewall',
                'Implement application-layer firewall rules',
                'Monitor for data exfiltration',
                'Check for malware using covert channels',
                'Review network baseline',
                'Document findings for security review'
            ]
        },
        'NETWORK_RECONNAISSANCE': {
            'severity': 'MEDIUM',
            'auto_action': 'BLOCK_IP',
            'confidence': 75,
            'description': 'Network reconnaissance detected - service enumeration attempt',
            'preventive_steps': [
                'Block the source IP',
                'Review exposed services',
                'Disable unnecessary services',
                'Implement service hardening',
                'Enable authentication for all services',
                'Review firewall rules',
                'Monitor for exploitation attempts',
                'Document the reconnaissance activity'
            ]
        },
        'SYN_FLOOD': {
            'severity': 'HIGH',
            'auto_action': 'BLOCK_IP',
            'confidence': 85,
            'description': 'SYN flood attack detected - possible DDoS',
            'preventive_steps': [
                'Enable SYN cookies in firewall',
                'Rate limit incoming connections',
                'Block source IPs if possible',
                'Contact ISP for upstream filtering',
                'Enable DDoS protection if available',
                'Monitor system resources',
                'Consider temporary service shutdown',
                'Document attack for reporting'
            ]
        },
        'SUSPICIOUS_PORT_CONNECTION': {
            'severity': 'MEDIUM',
            'auto_action': 'ALERT_ONLY',
            'confidence': 65,
            'description': 'Connection to suspicious port detected - possible malware communication',
            'preventive_steps': [
                'Identify the process making the connection',
                'Research the port usage',
                'Block the destination if malicious',
                'Scan system for malware',
                'Review firewall outbound rules',
                'Monitor for additional suspicious connections',
                'Check process reputation',
                'Document findings'
            ]
        }
    }
    
    def __init__(self):
        # Tracking state
        self.port_scan_tracker = defaultdict(lambda: {'ports': set(), 'first_seen': None})
        self.connection_history = defaultdict(list)
        self.dns_query_tracker = defaultdict(list)
        self.arp_table = {}  # IP -> MAC mappings
        self.threat_cooldowns = {}  # threat_key -> last_alert_time
        
        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'threats_by_type': defaultdict(int)
        }
    
    def analyze_packet_data(self, packet_data: Dict) -> Optional[NetworkThreat]:
        """
        Analyze packet data for network threats.
        
        Args:
            packet_data: Dictionary containing packet information
        
        Returns:
            NetworkThreat if threat detected, None otherwise
        """
        self.stats['total_analyzed'] += 1
        
        threat = None
        
        # Extract packet information
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        src_port = packet_data.get('src_port')
        dst_port = packet_data.get('dst_port')
        protocol = packet_data.get('protocol')
        length = packet_data.get('length', 0)
        flags = packet_data.get('flags')
        payload = packet_data.get('payload_preview')
        is_suspicious = packet_data.get('is_suspicious', False)
        threat_type = packet_data.get('threat_type')
        confidence = packet_data.get('confidence', 0)
        
        # Check for specific threat types
        if threat_type:
            threat = self._classify_threat(
                threat_type=threat_type,
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=dst_port,
                protocol=protocol,
                confidence=confidence,
                evidence=[payload] if payload else []
            )
        
        # Additional analysis based on packet characteristics
        if not threat:
            # DNS analysis
            if protocol == 'DNS' and length > 512:
                threat = self._detect_dns_tunneling(
                    dst_ip=dst_ip,
                    query=payload,
                    length=length
                )
            
            # ICMP analysis
            if protocol == 'ICMP' and length > 1000:
                threat = self._detect_icmp_tunneling(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    length=length
                )
            
            # TCP SYN analysis
            if protocol == 'TCP' and flags and 'S' in str(flags):
                threat = self._detect_syn_flood(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port
                )
        
        if threat:
            self.stats['threats_detected'] += 1
            self.stats['threats_by_type'][threat.type] += 1
            logger.warning(f"Network threat detected: {threat.type} (confidence: {threat.confidence}%)")
        
        return threat
    
    def _classify_threat(self, 
                        threat_type: str,
                        src_ip: Optional[str],
                        dst_ip: Optional[str],
                        port: Optional[int],
                        protocol: Optional[str],
                        confidence: int,
                        evidence: List[str]) -> Optional[NetworkThreat]:
        """Classify and create threat alert"""
        
        # Check cooldown to avoid alert fatigue
        threat_key = f"{threat_type}_{src_ip}_{dst_ip}"
        current_time = time.time()
        if threat_key in self.threat_cooldowns:
            if current_time - self.threat_cooldowns[threat_key] < 60:  # 1 minute cooldown
                return None
        
        self.threat_cooldowns[threat_key] = current_time
        
        # Get threat configuration
        config = self.NETWORK_THREAT_RESPONSES.get(threat_type, {})
        if not config:
            # Unknown threat type - create generic alert
            config = {
                'severity': 'MEDIUM',
                'auto_action': 'ALERT_ONLY',
                'description': f'Network anomaly detected: {threat_type}',
                'preventive_steps': ['Investigate the network activity', 'Review firewall logs']
            }
        
        return NetworkThreat(
            type=threat_type,
            severity=config.get('severity', 'MEDIUM'),
            confidence=max(confidence, config.get('confidence', 70)),
            description=config.get('description', 'Network threat detected'),
            source_ip=src_ip,
            destination_ip=dst_ip,
            port=port,
            protocol=protocol,
            evidence=evidence,
            auto_action=config.get('auto_action', 'ALERT_ONLY'),
            preventive_steps=config.get('preventive_steps', []),
            detected_at=datetime.datetime.now().isoformat()
        )
    
    def _detect_dns_tunneling(self, 
                             dst_ip: Optional[str],
                             query: Optional[str],
                             length: int) -> Optional[NetworkThreat]:
        """Detect DNS tunneling attempts"""
        
        # Track DNS queries
        if dst_ip:
            self.dns_query_tracker[dst_ip].append({
                'time': time.time(),
                'length': length,
                'query': query
            })
            
            # Keep only recent queries
            cutoff = time.time() - 300  # 5 minutes
            self.dns_query_tracker[dst_ip] = [
                q for q in self.dns_query_tracker[dst_ip]
                if q['time'] > cutoff
            ]
            
            # Check for sustained large DNS queries
            recent = self.dns_query_tracker[dst_ip]
            if len(recent) > 10:
                avg_length = sum(q['length'] for q in recent) / len(recent)
                if avg_length > 400:
                    return self._classify_threat(
                        threat_type='DNS_TUNNELING',
                        src_ip=None,
                        dst_ip=dst_ip,
                        port=53,
                        protocol='DNS',
                        confidence=85,
                        evidence=[f"Average DNS query size: {avg_length:.0f} bytes"]
                    )
        
        return None
    
    def _detect_icmp_tunneling(self,
                              src_ip: Optional[str],
                              dst_ip: Optional[str],
                              length: int) -> Optional[NetworkThreat]:
        """Detect ICMP tunneling attempts"""
        
        if length > 1000:
            return self._classify_threat(
                threat_type='ICMP_TUNNELING',
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=None,
                protocol='ICMP',
                confidence=75,
                evidence=[f"Oversized ICMP packet: {length} bytes"]
            )
        
        return None
    
    def _detect_syn_flood(self,
                         src_ip: Optional[str],
                         dst_ip: Optional[str],
                         dst_port: Optional[int]) -> Optional[NetworkThreat]:
        """Detect SYN flood attacks"""
        
        if src_ip and dst_ip:
            key = f"{src_ip}_{dst_ip}"
            if key not in self.port_scan_tracker:
                self.port_scan_tracker[key] = {'count': 0, 'first_seen': time.time()}
            
            self.port_scan_tracker[key]['count'] += 1
            
            # Check for high rate of SYN packets
            elapsed = time.time() - self.port_scan_tracker[key]['first_seen']
            if elapsed > 0 and elapsed < 10:  # Within 10 seconds
                rate = self.port_scan_tracker[key]['count'] / elapsed
                if rate > 100:  # More than 100 SYN packets per second
                    return self._classify_threat(
                        threat_type='SYN_FLOOD',
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        port=dst_port,
                        protocol='TCP',
                        confidence=85,
                        evidence=[f"SYN rate: {rate:.0f} packets/second"]
                    )
        
        return None
    
    def analyze_connection_pattern(self, 
                                   connections: List[Dict]) -> Optional[NetworkThreat]:
        """
        Analyze connection patterns for C2 beaconing.
        
        Args:
            connections: List of connection records with timestamps
        
        Returns:
            NetworkThreat if beaconing detected
        """
        # Group connections by destination
        by_destination = defaultdict(list)
        for conn in connections:
            dst = conn.get('remote_ip') or conn.get('dst_ip')
            if dst:
                by_destination[dst].append(conn)
        
        # Check each destination for beaconing
        for dst_ip, conns in by_destination.items():
            if len(conns) < 5:
                continue
            
            # Extract timestamps and calculate intervals
            timestamps = sorted([
                conn.get('timestamp') or conn.get('time', 0)
                for conn in conns
            ])
            
            if len(timestamps) < 5:
                continue
            
            # Convert to numeric if needed
            numeric_timestamps = []
            for ts in timestamps:
                if isinstance(ts, str):
                    try:
                        numeric_timestamps.append(datetime.datetime.fromisoformat(ts).timestamp())
                    except:
                        continue
                else:
                    numeric_timestamps.append(float(ts))
            
            if len(numeric_timestamps) < 5:
                continue
            
            # Calculate intervals
            intervals = [
                numeric_timestamps[i+1] - numeric_timestamps[i]
                for i in range(len(numeric_timestamps)-1)
            ]
            
            if not intervals:
                continue
            
            # Check for regular intervals (low variance)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            
            # Known C2 intervals (30s, 60s, 5min, 15min, 1 hour)
            c2_intervals = [30, 60, 120, 300, 900, 1800, 3600]
            
            for c2_interval in c2_intervals:
                if abs(avg_interval - c2_interval) < 10 and variance < 25:
                    return self._classify_threat(
                        threat_type='C2_BEACONING',
                        src_ip=None,
                        dst_ip=dst_ip,
                        port=None,
                        protocol='TCP',
                        confidence=92,
                        evidence=[
                            f"Regular connections every {avg_interval:.0f}s",
                            f"Variance: {variance:.2f}",
                            f"Connection count: {len(conns)}"
                        ]
                    )
        
        return None
    
    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'total_analyzed': self.stats['total_analyzed'],
            'threats_detected': self.stats['threats_detected'],
            'threats_by_type': dict(self.stats['threats_by_type']),
            'tracked_sources': len(self.port_scan_tracker),
            'tracked_destinations': len(self.connection_history)
        }
    
    def reset(self):
        """Reset detector state"""
        self.port_scan_tracker.clear()
        self.connection_history.clear()
        self.dns_query_tracker.clear()
        self.threat_cooldowns.clear()
        self.stats = {
            'total_analyzed': 0,
            'threats_detected': 0,
            'threats_by_type': defaultdict(int)
        }


# Integration helper
def create_network_threat_alert(threat: NetworkThreat) -> Dict:
    """
    Convert NetworkThreat to format compatible with main detector.
    
    Args:
        threat: NetworkThreat object
    
    Returns:
        Dictionary compatible with main threat alert system
    """
    severity_colors = {
        'CRITICAL': '#ef4444',
        'HIGH': '#f97316',
        'MEDIUM': '#eab308',
        'LOW': '#22c55e'
    }
    
    severity_icons = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': 'ℹ️'
    }
    
    return {
        'type': threat.type,
        'severity': threat.severity,
        'confidence': threat.confidence,
        'description': threat.description,
        'detected_at': threat.detected_at,
        'status': 'ACTIVE',
        'auto_action': threat.auto_action,
        'preventive_steps': threat.preventive_steps,
        'user_message': f"Network threat detected: {threat.type}",
        'icon': severity_icons.get(threat.severity, '⚠️'),
        'color': severity_colors.get(threat.severity, '#eab308'),
        'immediate_action': threat.auto_action,
        'source_ip': threat.source_ip,
        'destination_ip': threat.destination_ip,
        'port': threat.port,
        'protocol': threat.protocol,
        'evidence': threat.evidence
    }


if __name__ == "__main__":
    # Test network detector
    logging.basicConfig(level=logging.INFO)
    
    print("[SENTINEL] Network Threat Detector Test")
    print("=" * 50)
    
    detector = NetworkThreatDetector()
    
    # Test packet data
    test_packets = [
        {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': 22,
            'protocol': 'TCP',
            'is_suspicious': True,
            'threat_type': 'PORT_SCAN_DETECTED',
            'confidence': 85
        },
        {
            'src_ip': '192.168.1.50',
            'dst_ip': '8.8.8.8',
            'protocol': 'DNS',
            'length': 600,
            'payload_preview': 'exfil-data.evil.com'
        },
        {
            'src_ip': '192.168.1.50',
            'dst_ip': '10.0.0.1',
            'protocol': 'ICMP',
            'length': 1500
        }
    ]
    
    print("\n[*] Testing packet analysis...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\n  Packet {i}:")
        threat = detector.analyze_packet_data(packet)
        if threat:
            print(f"    ⚠️  THREAT: {threat.type}")
            print(f"    Severity: {threat.severity}")
            print(f"    Confidence: {threat.confidence}%")
        else:
            print(f"    ✓ No threat detected")
    
    print("\n[*] Statistics:")
    stats = detector.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n[OK] Network detector test completed")
