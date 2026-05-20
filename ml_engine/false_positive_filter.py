"""
SENTINEL - Enhanced False Positive Filtering Engine
===================================================
Advanced filtering system to eliminate false positives while maintaining
high detection accuracy for genuine threats.

Features:
- Context-aware validation
- Behavioral baseline comparison
- Multi-signal correlation
- Adaptive confidence scoring
- Whitelist management
- Threat intelligence integration
"""

import logging
import datetime
import json
import os
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum

logger = logging.getLogger('SENTINEL.FalsePositiveFilter')


class ValidationResult(Enum):
    """Validation result types"""
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    SUPPRESSED = "SUPPRESSED"


@dataclass
class FilterContext:
    """Context information for threat validation"""
    threat: Dict[str, Any]
    system_state: Dict[str, Any]
    historical_data: List[Dict[str, Any]]
    user_activity: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())


@dataclass
class FilterResult:
    """Result of false positive filtering"""
    original_threat: Dict[str, Any]
    validation_result: ValidationResult
    confidence_adjustment: float
    suppression_reason: Optional[str]
    filter_metadata: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_threat": self.original_threat,
            "validation_result": self.validation_result.value,
            "confidence_adjustment": self.confidence_adjustment,
            "suppression_reason": self.suppression_reason,
            "filter_metadata": self.filter_metadata,
            "timestamp": self.timestamp
        }


class WhitelistManager:
    """
    Manages whitelists for processes, IPs, domains, and behaviors.
    Supports dynamic learning and manual curation.
    """

    def __init__(self, whitelist_file: str = None):
        self.whitelist_file = whitelist_file or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'whitelist.json'
        )
        
        # Process whitelist - known safe processes
        self.safe_processes: Set[str] = {
            # Windows system processes
            "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
            "services.exe", "lsass.exe", "winlogon.exe", "dwm.exe",
            "explorer.exe", "svchost.exe", "conhost.exe", "runtimebroker.exe",
            "fontdrvhost.exe", "ctfmon.exe", "sihost.exe", "dashhost.exe",
            "shellexperiencehost.exe", "startmenuexperiencehost.exe",
            "applicationframehost.exe", "microsoft.store.exe", "winstore.app.exe",
            
            # Security processes
            "smartscreen.exe", "msmpeng.exe", "nissrv.exe", 
            "securityhealthservice.exe", "compattelrunner.exe",
            
            # Development tools
            "code.exe", "python.exe", "node.exe", "cmd.exe", "powershell.exe",
            "notepad.exe", "taskmgr.exe",
            
            # Browsers
            "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
            
            # Virtualization
            "vmware-usbarbitrator64.exe", "vmware-authd.exe", "vmnat.exe",
            "vmnetdhcp.exe", "vmware-vmx.exe",
            
            # Communication
            "teams.exe", "slack.exe", "discord.exe", "zoom.exe",
            
            # Media
            "spotify.exe", "vlc.exe",
            
            # Utilities
            "obs64.exe", "obs32.exe", "snippingtool.exe"
        }
        
        # Safe IP ranges (private networks, CDN, major services)
        self.safe_ip_ranges: Set[str] = {
            "127.0.0.0/8",      # Localhost
            "10.0.0.0/8",       # Private Class A
            "172.16.0.0/12",    # Private Class B
            "192.168.0.0/16",   # Private Class C
            "169.254.0.0/16",   # Link-local
            "224.0.0.0/4",      # Multicast
            "0.0.0.0/8",        # Current network
        }
        
        # Safe domains (major CDNs, cloud providers, etc.)
        self.safe_domains: Set[str] = {
            "microsoft.com", "windows.com", "windowsupdate.com",
            "google.com", "googleapis.com", "gstatic.com",
            "cloudflare.com", "amazonaws.com", "azure.com",
            "akamai.com", "akamaihd.com", "akamaized.net",
            "fastly.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
            "github.com", "githubusercontent.com",
            "apple.com", "icloud.com",
            "facebook.com", "fbcdn.net",
            "twitter.com", "twimg.com",
            "linkedin.com", "licdn.com",
            "netflix.com", "nflxext.com", "nflximg.com",
            "spotify.com", "scdn.co",
            "zoom.us", "zoom.com",
            "slack.com", "slack-edge.com",
            "discord.com", "discordapp.com", "discord.gg"
        }
        
        # Safe behaviors (normal system activities)
        self.safe_behaviors: Set[str] = {
            "windows_update",
            "browser_navigation",
            "file_explorer_browsing",
            "development_activity",
            "media_playback",
            "office_productivity",
            "system_maintenance",
            "antivirus_scan",
            "backup_activity",
            "cloud_sync"
        }
        
        # Load custom whitelist if exists
        self._load_custom_whitelist()
        
        logger.info(f"WhitelistManager initialized with {len(self.safe_processes)} safe processes")

    def _load_custom_whitelist(self):
        """Load custom whitelist from file"""
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    custom = json.load(f)
                    
                if 'processes' in custom:
                    self.safe_processes.update(custom['processes'])
                if 'domains' in custom:
                    self.safe_domains.update(custom['domains'])
                if 'behaviors' in custom:
                    self.safe_behaviors.update(custom['behaviors'])
                    
                logger.info(f"Loaded custom whitelist from {self.whitelist_file}")
        except Exception as e:
            logger.warning(f"Could not load custom whitelist: {e}")

    def save_custom_whitelist(self):
        """Save current whitelist to file"""
        try:
            os.makedirs(os.path.dirname(self.whitelist_file), exist_ok=True)
            with open(self.whitelist_file, 'w') as f:
                json.dump({
                    'processes': list(self.safe_processes),
                    'domains': list(self.safe_domains),
                    'behaviors': list(self.safe_behaviors),
                    'updated_at': datetime.datetime.utcnow().isoformat()
                }, f, indent=2)
            logger.info(f"Saved whitelist to {self.whitelist_file}")
        except Exception as e:
            logger.error(f"Could not save whitelist: {e}")

    def is_safe_process(self, process_name: str) -> bool:
        """Check if process is in safe list"""
        return process_name.lower() in [p.lower() for p in self.safe_processes]

    def is_safe_ip(self, ip: str) -> bool:
        """Check if IP is in safe ranges"""
        # Simple check for private IPs
        return (
            ip.startswith("127.") or
            ip.startswith("10.") or
            ip.startswith("192.168.") or
            ip.startswith("172.16.") or
            ip.startswith("172.17.") or
            ip.startswith("172.18.") or
            ip.startswith("172.19.") or
            ip.startswith("172.2") or
            ip.startswith("172.30.") or
            ip.startswith("172.31.") or
            ip == "0.0.0.0" or
            ip == "::1"
        )

    def is_safe_domain(self, domain: str) -> bool:
        """Check if domain is in safe list"""
        domain_lower = domain.lower()
        return any(safe in domain_lower for safe in self.safe_domains)

    def add_safe_process(self, process_name: str):
        """Add process to safe list"""
        self.safe_processes.add(process_name.lower())
        logger.info(f"Added {process_name} to safe process whitelist")

    def remove_safe_process(self, process_name: str):
        """Remove process from safe list"""
        self.safe_processes.discard(process_name.lower())
        logger.info(f"Removed {process_name} from safe process whitelist")


class ContextValidator:
    """
    Validates threats based on system context and user activity.
    Reduces false positives by understanding normal behavior patterns.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.ContextValidator')
        
        # Normal activity patterns
        self.normal_patterns = {
            'high_cpu_processes': {
                'video_encoding': ['ffmpeg', 'handbrake', 'premiere', 'davinci'],
                'compilation': ['gcc', 'g++', 'msbuild', 'javac', 'cargo'],
                'gaming': ['game', 'steam', 'epic', 'unity', 'unreal'],
                'virtualization': ['vmware', 'virtualbox', 'hyper-v', 'docker'],
                '3d_rendering': ['blender', 'maya', '3dsmax', 'cinema4d']
            },
            'high_network_processes': {
                'browsers': ['chrome', 'firefox', 'edge', 'brave', 'opera'],
                'streaming': ['netflix', 'spotify', 'vlc', 'youtube'],
                'cloud_sync': ['onedrive', 'dropbox', 'googledrive', 'icloud'],
                'development': ['git', 'npm', 'pip', 'docker', 'kubectl']
            },
            'high_disk_processes': {
                'backup': ['backup', 'sync', 'timemachine', 'acronis'],
                'compression': ['winrar', '7zip', 'winzip', 'tar'],
                'database': ['sql', 'mysql', 'postgres', 'mongo', 'redis'],
                'virtualization': ['vmware', 'virtualbox', 'hyper-v']
            }
        }

    def validate_threat_context(self, threat: Dict[str, Any], 
                                 system_state: Dict[str, Any],
                                 processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """
        Validate if threat is genuine based on context.
        
        Returns:
            Tuple of (is_genuine, reason)
        """
        threat_type = threat.get('type', '')
        
        # Check for ransomware false positives
        if 'RANSOMWARE' in threat_type:
            return self._validate_ransomware_context(threat, system_state, processes)
        
        # Check for DDoS false positives
        if 'DDOS' in threat_type:
            return self._validate_ddos_context(threat, system_state, processes)
        
        # Check for cryptominer false positives
        if 'CRYPTOMINER' in threat_type or 'CRYPTOJACKING' in threat_type:
            return self._validate_cryptominer_context(threat, processes)
        
        # Check for data exfiltration false positives
        if 'EXFILTRATION' in threat_type:
            return self._validate_exfiltration_context(threat, system_state, processes)
        
        # Check for process injection false positives
        if 'INJECTION' in threat_type:
            return self._validate_injection_context(threat, processes)
        
        # Default: assume genuine if no specific validation
        return True, "No specific context validation available"

    def _validate_ransomware_context(self, threat: Dict[str, Any],
                                      system_state: Dict[str, Any],
                                      processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Validate ransomware detection context"""
        # Check if high disk activity is from legitimate backup/encoding
        disk_percent = system_state.get('disk_percent', 0)
        
        if disk_percent > 90:
            # Check if any legitimate high-disk process is running
            for proc in processes:
                proc_name = (proc.get('name') or '').lower()
                for category, patterns in self.normal_patterns['high_disk_processes'].items():
                    if any(p in proc_name for p in patterns):
                        return False, f"High disk activity from legitimate {category} process: {proc_name}"
        
        # Check if encryption-related process is known safe
        target_pids = threat.get('target_pids', [])
        for pid in target_pids:
            proc = next((p for p in processes if p.get('pid') == pid), None)
            if proc:
                proc_name = (proc.get('name') or '').lower()
                if proc_name in ['backup.exe', 'sync.exe', 'winrar.exe', '7z.exe']:
                    return False, f"Encryption activity from legitimate process: {proc_name}"
        
        return True, "Ransomware context validated"

    def _validate_ddos_context(self, threat: Dict[str, Any],
                                system_state: Dict[str, Any],
                                processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Validate DDoS detection context"""
        # Check if high network activity is from legitimate streaming/download
        network = system_state.get('network', {})
        bytes_recv = network.get('bytes_recv', 0)
        
        # If receiving large amounts of data, check if it's from streaming
        if bytes_recv > 1_000_000_000:  # > 1GB
            for proc in processes:
                proc_name = (proc.get('name') or '').lower()
                for category, patterns in self.normal_patterns['high_network_processes'].items():
                    if any(p in proc_name for p in patterns):
                        return False, f"High network activity from legitimate {category}: {proc_name}"
        
        return True, "DDoS context validated"

    def _validate_cryptominer_context(self, threat: Dict[str, Any],
                                       processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Validate cryptominer detection context"""
        # Check if high CPU is from legitimate intensive process
        target_pids = threat.get('target_pids', [])
        
        for pid in target_pids:
            proc = next((p for p in processes if p.get('pid') == pid), None)
            if proc:
                proc_name = (proc.get('name') or '').lower()
                cpu_percent = proc.get('cpu_percent', 0)
                
                # High CPU from known intensive processes is normal
                if cpu_percent > 80:
                    for category, patterns in self.normal_patterns['high_cpu_processes'].items():
                        if any(p in proc_name for p in patterns):
                            return False, f"High CPU from legitimate {category}: {proc_name}"
        
        return True, "Cryptominer context validated"

    def _validate_exfiltration_context(self, threat: Dict[str, Any],
                                        system_state: Dict[str, Any],
                                        processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Validate data exfiltration detection context"""
        # Check if high outbound traffic is from cloud sync or backup
        target_ips = threat.get('target_ips', [])
        
        # Known safe cloud services
        safe_cloud_ips = [
            'onedrive', 'dropbox', 'google', 'amazonaws', 'azure',
            'icloud', 'backblaze', 'carbonite'
        ]
        
        for ip in target_ips:
            # Check if IP belongs to known safe cloud service
            # This is simplified - in production, use IP reputation databases
            if any(service in ip.lower() for service in safe_cloud_ips):
                return False, f"High traffic to known cloud service: {ip}"
        
        return True, "Data exfiltration context validated"

    def _validate_injection_context(self, threat: Dict[str, Any],
                                     processes: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Validate process injection detection context"""
        # Some legitimate applications use DLL injection
        target_pids = threat.get('target_pids', [])
        
        legitimate_injection_processes = {
            'steam.exe', 'epicgameslauncher.exe', 'origin.exe',
            'discord.exe', 'slack.exe', 'teams.exe',
            'antivirus', 'security', 'monitoring'
        }
        
        for pid in target_pids:
            proc = next((p for p in processes if p.get('pid') == pid), None)
            if proc:
                proc_name = (proc.get('name') or '').lower()
                if any(legit in proc_name for legit in legitimate_injection_processes):
                    return False, f"Injection from legitimate application: {proc_name}"
        
        return True, "Process injection context validated"


class BehavioralAnalyzer:
    """
    Analyzes behavioral patterns to distinguish between normal and malicious activity.
    Uses statistical baselines and anomaly detection.
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.logger = logging.getLogger('SENTINEL.BehavioralAnalyzer')
        
        # Historical data for baseline learning
        self.cpu_history: deque = deque(maxlen=window_size)
        self.ram_history: deque = deque(maxlen=window_size)
        self.network_history: deque = deque(maxlen=window_size)
        self.process_count_history: deque = deque(maxlen=window_size)
        
        # Behavioral patterns
        self.suspicious_sequences: List[List[str]] = [
            # Ransomware-like sequence
            ['high_cpu', 'high_disk', 'file_modification', 'network_disconnect'],
            # Data theft sequence
            ['process_injection', 'network_connection', 'data_access', 'high_upload'],
            # Backdoor sequence
            ['suspicious_process', 'network_listener', 'privilege_escalation', 'persistence']
        ]

    def update_baseline(self, system_state: Dict[str, Any]):
        """Update behavioral baseline with new data"""
        self.cpu_history.append(system_state.get('cpu_percent', 0))
        self.ram_history.append(system_state.get('ram_percent', 0))
        self.network_history.append(system_state.get('network', {}).get('bytes_sent', 0))
        self.process_count_history.append(len(system_state.get('processes', [])))

    def is_anomalous_behavior(self, threat: Dict[str, Any], 
                               system_state: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determine if threat represents anomalous behavior.
        
        Returns:
            Tuple of (is_anomalous, anomaly_score)
        """
        if len(self.cpu_history) < 10:
            return False, 0.0  # Not enough data
        
        anomaly_scores = []
        
        # Check CPU anomaly
        current_cpu = system_state.get('cpu_percent', 0)
        avg_cpu = sum(self.cpu_history) / len(self.cpu_history)
        if avg_cpu > 0:
            cpu_anomaly = abs(current_cpu - avg_cpu) / avg_cpu
            anomaly_scores.append(min(cpu_anomaly, 1.0))
        
        # Check RAM anomaly
        current_ram = system_state.get('ram_percent', 0)
        avg_ram = sum(self.ram_history) / len(self.ram_history)
        if avg_ram > 0:
            ram_anomaly = abs(current_ram - avg_ram) / avg_ram
            anomaly_scores.append(min(ram_anomaly, 1.0))
        
        # Check network anomaly
        current_net = system_state.get('network', {}).get('bytes_sent', 0)
        avg_net = sum(self.network_history) / len(self.network_history)
        if avg_net > 0:
            net_anomaly = abs(current_net - avg_net) / avg_net
            anomaly_scores.append(min(net_anomaly, 1.0))
        
        if not anomaly_scores:
            return False, 0.0
        
        overall_anomaly = sum(anomaly_scores) / len(anomaly_scores)
        
        # Consider anomalous if score > 0.7
        return overall_anomaly > 0.7, overall_anomaly


class ThreatCorrelator:
    """
    Correlates multiple threat indicators to reduce duplicate alerts
    and identify coordinated attacks.
    """

    def __init__(self, correlation_window: int = 300):  # 5 minutes
        self.correlation_window = correlation_window
        self.recent_threats: List[Dict[str, Any]] = []
        self.logger = logging.getLogger('SENTINEL.ThreatCorrelator')

    def correlate_threats(self, new_threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate new threats with recent history to:
        1. Remove duplicates
        2. Group related threats
        3. Identify attack campaigns
        """
        if not new_threats:
            return []
        
        # Clean old threats from history
        current_time = datetime.datetime.utcnow()
        self.recent_threats = [
            t for t in self.recent_threats
            if (current_time - datetime.datetime.fromisoformat(t.get('detected_at', current_time.isoformat()))).seconds < self.correlation_window
        ]
        
        # Filter duplicates and related threats
        filtered_threats = []
        for threat in new_threats:
            if not self._is_duplicate(threat):
                filtered_threats.append(threat)
                self.recent_threats.append(threat)
        
        # Group related threats
        grouped = self._group_related_threats(filtered_threats)
        
        return grouped

    def _is_duplicate(self, threat: Dict[str, Any]) -> bool:
        """Check if threat is duplicate of recent threat"""
        threat_type = threat.get('type', '')
        target_pids = set(threat.get('target_pids', []))
        target_ips = set(threat.get('target_ips', []))
        
        for recent in self.recent_threats:
            # Same type
            if recent.get('type') != threat_type:
                continue
            
            # Same targets
            recent_pids = set(recent.get('target_pids', []))
            recent_ips = set(recent.get('target_ips', []))
            
            if target_pids and target_pids == recent_pids:
                return True
            if target_ips and target_ips == recent_ips:
                return True
        
        return False

    def _group_related_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group related threats into single alerts"""
        if len(threats) <= 1:
            return threats
        
        # Group by target process/IP
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        for threat in threats:
            # Create group key based on targets
            pids = tuple(sorted(threat.get('target_pids', [])))
            ips = tuple(sorted(threat.get('target_ips', [])))
            key = f"{pids}_{ips}"
            groups[key].append(threat)
        
        # Merge groups with multiple threats
        merged_threats = []
        for key, group_threats in groups.items():
            if len(group_threats) == 1:
                merged_threats.append(group_threats[0])
            else:
                # Create merged threat
                merged = self._merge_threat_group(group_threats)
                merged_threats.append(merged)
        
        return merged_threats

    def _merge_threat_group(self, threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge multiple related threats into single alert"""
        # Use highest severity threat as base
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        base_threat = max(threats, key=lambda t: severity_order.get(t.get('severity', 'LOW'), 0))
        
        # Combine descriptions
        descriptions = [t.get('description', '') for t in threats]
        combined_desc = f"Multiple related threats detected: {'; '.join(set(descriptions))}"
        
        # Use highest confidence
        max_confidence = max(t.get('confidence', 0) for t in threats)
        
        # Combine preventive steps
        all_steps = []
        for t in threats:
            all_steps.extend(t.get('preventive_steps', []))
        unique_steps = list(dict.fromkeys(all_steps))  # Remove duplicates while preserving order
        
        return {
            **base_threat,
            'type': f"MULTIPLE_{base_threat.get('type', 'THREATS')}",
            'description': combined_desc,
            'confidence': max_confidence,
            'preventive_steps': unique_steps[:10],  # Limit to top 10
            'related_threats': [t.get('type') for t in threats if t != base_threat]
        }


class FalsePositiveFilter:
    """
    Main false positive filtering engine that coordinates all filtering components.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger('SENTINEL.FalsePositiveFilter')
        
        # Initialize components
        self.whitelist_manager = WhitelistManager(
            self.config.get('whitelist_file')
        )
        self.context_validator = ContextValidator()
        self.behavioral_analyzer = BehavioralAnalyzer(
            self.config.get('baseline_window', 100)
        )
        self.threat_correlator = ThreatCorrelator(
            self.config.get('correlation_window', 300)
        )
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'false_positives_filtered': 0,
            'true_positives_confirmed': 0,
            'suppressed': 0,
            'needs_review': 0
        }
        
        self.logger.info("FalsePositiveFilter initialized")

    def filter_threats(self, threats: List[Dict[str, Any]], 
                       system_state: Dict[str, Any],
                       processes: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[FilterResult]]:
        """
        Filter threats to remove false positives.
        
        Args:
            threats: List of detected threats
            system_state: Current system state
            processes: List of running processes
            
        Returns:
            Tuple of (filtered_threats, filter_results)
        """
        if not threats:
            return [], []
        
        self.stats['total_processed'] += len(threats)
        
        # Update behavioral baseline
        self.behavioral_analyzer.update_baseline(system_state)
        
        # Step 1: Whitelist filtering
        whitelist_filtered = self._apply_whitelist_filter(threats, processes)
        
        # Step 2: Context validation
        context_validated = self._apply_context_validation(
            whitelist_filtered, system_state, processes
        )
        
        # Step 3: Behavioral analysis
        behavior_validated = self._apply_behavioral_analysis(
            context_validated, system_state
        )
        
        # Step 4: Threat correlation
        correlated = self.threat_correlator.correlate_threats(behavior_validated)
        
        # Step 5: Confidence adjustment
        final_threats, filter_results = self._adjust_confidence(correlated)
        
        # Update statistics
        self._update_statistics(filter_results)
        
        self.logger.info(
            f"Filtered {len(threats)} threats → {len(final_threats)} genuine threats "
            f"({self.stats['false_positives_filtered']} false positives removed)"
        )
        
        return final_threats, filter_results

    def _apply_whitelist_filter(self, threats: List[Dict[str, Any]], 
                                 processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter threats based on whitelist"""
        filtered = []
        
        for threat in threats:
            # Check if target process is whitelisted
            target_pids = threat.get('target_pids', [])
            if target_pids:
                whitelisted = False
                for pid in target_pids:
                    proc = next((p for p in processes if p.get('pid') == pid), None)
                    if proc:
                        proc_name = proc.get('name', '')
                        if self.whitelist_manager.is_safe_process(proc_name):
                            whitelisted = True
                            self.logger.debug(
                                f"Suppressed {threat.get('type')} - whitelisted process: {proc_name}"
                            )
                            break
                
                if whitelisted:
                    self.stats['suppressed'] += 1
                    continue
            
            # Check if target IP is whitelisted
            target_ips = threat.get('target_ips', [])
            if target_ips:
                whitelisted = False
                for ip in target_ips:
                    if self.whitelist_manager.is_safe_ip(ip):
                        whitelisted = True
                        self.logger.debug(
                            f"Suppressed {threat.get('type')} - whitelisted IP: {ip}"
                        )
                        break
                
                if whitelisted:
                    self.stats['suppressed'] += 1
                    continue
            
            filtered.append(threat)
        
        return filtered

    def _apply_context_validation(self, threats: List[Dict[str, Any]],
                                   system_state: Dict[str, Any],
                                   processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate threats based on context"""
        validated = []
        
        for threat in threats:
            is_genuine, reason = self.context_validator.validate_threat_context(
                threat, system_state, processes
            )
            
            if is_genuine:
                validated.append(threat)
            else:
                self.logger.info(
                    f"Filtered false positive {threat.get('type')}: {reason}"
                )
                self.stats['false_positives_filtered'] += 1
        
        return validated

    def _apply_behavioral_analysis(self, threats: List[Dict[str, Any]],
                                    system_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Validate threats based on behavioral analysis"""
        validated = []
        
        for threat in threats:
            is_anomalous, anomaly_score = self.behavioral_analyzer.is_anomalous_behavior(
                threat, system_state
            )
            
            # If behavior is not anomalous and threat is low confidence, filter it
            if not is_anomalous and threat.get('confidence', 0) < 70:
                self.logger.debug(
                    f"Filtered low-confidence non-anomalous threat: {threat.get('type')}"
                )
                self.stats['false_positives_filtered'] += 1
            else:
                # Add anomaly score to threat metadata
                threat['anomaly_score'] = anomaly_score
                validated.append(threat)
        
        return validated

    def _adjust_confidence(self, threats: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[FilterResult]]:
        """Adjust confidence scores based on filtering results"""
        final_threats = []
        filter_results = []
        
        for threat in threats:
            original_confidence = threat.get('confidence', 50)
            
            # Boost confidence for threats that passed all filters
            adjusted_confidence = min(original_confidence + 10, 100)
            
            # Create filter result
            result = FilterResult(
                original_threat=threat.copy(),
                validation_result=ValidationResult.TRUE_POSITIVE,
                confidence_adjustment=adjusted_confidence - original_confidence,
                suppression_reason=None,
                filter_metadata={
                    'whitelist_passed': True,
                    'context_validated': True,
                    'behavior_validated': True,
                    'correlation_checked': True
                }
            )
            
            # Update threat with adjusted confidence
            threat['confidence'] = adjusted_confidence
            threat['filter_validated'] = True
            
            final_threats.append(threat)
            filter_results.append(result)
            self.stats['true_positives_confirmed'] += 1
        
        return final_threats, filter_results

    def _update_statistics(self, filter_results: List[FilterResult]):
        """Update filtering statistics"""
        for result in filter_results:
            if result.validation_result == ValidationResult.NEEDS_REVIEW:
                self.stats['needs_review'] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get filtering statistics"""
        return {
            **self.stats,
            'false_positive_rate': (
                self.stats['false_positives_filtered'] / max(self.stats['total_processed'], 1) * 100
            ),
            'true_positive_rate': (
                self.stats['true_positives_confirmed'] / max(self.stats['total_processed'], 1) * 100
            )
        }

    def add_safe_process(self, process_name: str):
        """Add process to whitelist"""
        self.whitelist_manager.add_safe_process(process_name)

    def remove_safe_process(self, process_name: str):
        """Remove process from whitelist"""
        self.whitelist_manager.remove_safe_process(process_name)

    def save_whitelist(self):
        """Save whitelist to file"""
        self.whitelist_manager.save_custom_whitelist()


# ============================================================================
# INTEGRATION WITH SENTINEL DETECTOR
# ============================================================================

class EnhancedSentinelDetector:
    """
    Enhanced SentinelDetector with integrated false positive filtering.
    Drop-in replacement for the original SentinelDetector.
    """

    def __init__(self, quarantine_dir: str = None, log_dir: str = None,
                 filter_config: Dict[str, Any] = None):
        # Import original detector
        from ml_engine.detector import (
            RuleEngine, AnomalyDetector, ThreatClassifier, AutoResponseEngine
        )
        
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.auto_response = AutoResponseEngine(quarantine_dir, log_dir)
        
        # Add false positive filter
        self.fp_filter = FalsePositiveFilter(filter_config)
        
        self.threat_history: List[Dict] = []
        self.logger = logging.getLogger('SENTINEL.EnhancedDetector')
        self.logger.info("Enhanced SENTINEL Detector initialized with False Positive Filtering")

    def analyze(self, snapshot: Dict[str, Any], auto_respond: bool = True) -> Dict[str, Any]:
        """
        Enhanced analysis with false positive filtering.
        """
        try:
            # Update ML baseline
            self.anomaly_detector.update_baseline(snapshot)

            # Run rule-based detection
            rule_threats = self.rule_engine.analyze(snapshot)

            # Run ML anomaly detection
            anomaly_score, anomaly_reason = self.anomaly_detector.calculate_anomaly_score(snapshot)

            # Add ML anomaly as threat if score is high
            if anomaly_score > 0.75:
                rule_threats.append({
                    "type": "ANOMALY",
                    "severity": "HIGH" if anomaly_score > 0.85 else "MEDIUM",
                    "confidence": int(anomaly_score * 100),
                    "description": f"ML anomaly detected (score: {anomaly_score}). {anomaly_reason}",
                    "anomaly_score": anomaly_score,
                    "preventive_steps": [
                        "Review recently installed software",
                        "Check running processes for anything unfamiliar",
                        "Monitor your system for the next 30 minutes",
                        "Run a full antivirus scan",
                        "Restart PC if behavior continues",
                        "Check Windows Event Viewer for errors",
                        "Review network connections",
                        "Update SENTINEL detection rules"
                    ],
                    "auto_action": "ALERT_ONLY"
                })

            # Apply false positive filtering
            system_state = snapshot.get("system", {})
            processes = snapshot.get("processes", [])
            
            filtered_threats, filter_results = self.fp_filter.filter_threats(
                rule_threats, system_state, processes
            )

            # Classify filtered threats
            classified = [self.classifier.classify(t) for t in filtered_threats]
            self.threat_history.extend(classified)

            # Execute auto-responses for detected threats
            auto_response_results = []
            if auto_respond and classified:
                for threat in classified:
                    action_str = threat.get('auto_action', 'ALERT_ONLY')
                    try:
                        from ml_engine.detector import AutoAction
                        action = AutoAction(action_str)
                        result = self.auto_response.execute(action, threat)
                        auto_response_results.append(result.to_dict())
                        self.logger.info(f"Auto-response executed for {threat['type']}: {result.success}")
                    except ValueError:
                        self.logger.warning(f"Unknown auto_action: {action_str} for {threat['type']}")

            # Log detection results
            if classified:
                self.logger.info(f"Detected {len(classified)} genuine threats: {[t['type'] for t in classified]}")

            # Get filter statistics
            filter_stats = self.fp_filter.get_statistics()

            return {
                "threats": classified,
                "anomaly_score": anomaly_score,
                "anomaly_reason": anomaly_reason,
                "is_baseline_ready": self.anomaly_detector.is_trained,
                "baseline_progress": min(len(self.anomaly_detector.cpu_history), 20) * 5,
                "total_threats_detected": len(self.threat_history),
                "system_status": self._get_system_status(classified, anomaly_score),
                "auto_response_results": auto_response_results,
                "detection_timestamp": datetime.datetime.utcnow().isoformat(),
                "filter_statistics": filter_stats,
                "false_positives_filtered": filter_stats['false_positives_filtered']
            }

        except Exception as e:
            self.logger.error(f"Error during threat analysis: {e}")
            return {
                "threats": [],
                "anomaly_score": 0.0,
                "anomaly_reason": f"Error during analysis: {str(e)}",
                "is_baseline_ready": self.anomaly_detector.is_trained,
                "baseline_progress": min(len(self.anomaly_detector.cpu_history), 20) * 5,
                "total_threats_detected": len(self.threat_history),
                "system_status": "ERROR",
                "auto_response_results": [],
                "detection_timestamp": datetime.datetime.utcnow().isoformat(),
                "filter_statistics": {},
                "false_positives_filtered": 0
            }

    def _get_system_status(self, threats: List[Dict], anomaly_score: float) -> str:
        """Determine overall system status based on threats and anomaly score."""
        if any(t.get("severity") == "CRITICAL" for t in threats):
            return "CRITICAL"
        elif any(t.get("severity") == "HIGH" for t in threats) or anomaly_score > 0.75:
            return "WARNING"
        elif anomaly_score > 0.5:
            return "CAUTION"
        else:
            return "SAFE"

    def get_threat_statistics(self) -> Dict[str, Any]:
        """Get statistics about detected threats."""
        if not self.threat_history:
            return {
                "total_threats": 0,
                "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "by_type": {},
                "recent_threats": []
            }

        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        by_type = {}

        for threat in self.threat_history:
            severity = threat.get("severity", "LOW")
            threat_type = threat.get("type", "UNKNOWN")

            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_type[threat_type] = by_type.get(threat_type, 0) + 1

        return {
            "total_threats": len(self.threat_history),
            "by_severity": by_severity,
            "by_type": by_type,
            "recent_threats": self.threat_history[-10:]
        }

    def add_safe_process(self, process_name: str):
        """Add process to whitelist"""
        self.fp_filter.add_safe_process(process_name)

    def remove_safe_process(self, process_name: str):
        """Remove process from whitelist"""
        self.fp_filter.remove_safe_process(process_name)

    def save_whitelist(self):
        """Save whitelist to file"""
        self.fp_filter.save_whitelist()


if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  SENTINEL - Enhanced False Positive Filtering Engine")
    print("=" * 70)
    print()
    print("Features:")
    print("  - Whitelist management for processes, IPs, and domains")
    print("  - Context-aware threat validation")
    print("  - Behavioral baseline analysis")
    print("  - Threat correlation and deduplication")
    print("  - Adaptive confidence scoring")
    print()
    print("=" * 70)
