"""
SENTINEL - Intelligent Threat Prioritization Framework
======================================================
Advanced threat prioritization system that ranks threats based on:
- Potential impact on system integrity
- Urgency of response required
- Business criticality of affected assets
- Attack sophistication level
- Exploitability score
- Potential for lateral movement
- Data sensitivity at risk

Author: SENTINEL Development Team
Version: 2.0.0
"""

import logging
import datetime
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger('SENTINEL.ThreatPrioritizer')


class Priority(Enum):
    """Threat priority levels"""
    P0_CRITICAL = "P0_CRITICAL"      # Immediate action required
    P1_HIGH = "P1_HIGH"              # Action within 1 hour
    P2_MEDIUM = "P2_MEDIUM"          # Action within 24 hours
    P3_LOW = "P3_LOW"                # Action within 1 week
    P4_INFO = "P4_INFO"              # Informational only


class ImpactCategory(Enum):
    """Categories of potential impact"""
    DATA_BREACH = "DATA_BREACH"
    SYSTEM_COMPROMISE = "SYSTEM_COMPROMISE"
    SERVICE_DISRUPTION = "SERVICE_DISRUPTION"
    FINANCIAL_LOSS = "FINANCIAL_LOSS"
    REPUTATION_DAMAGE = "REPUTATION_DAMAGE"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"


@dataclass
class ThreatPriority:
    """Threat priority assessment result"""
    threat_id: str
    threat_type: str
    priority: Priority
    priority_score: float  # 0-100
    impact_score: float    # 0-100
    urgency_score: float   # 0-100
    exploitability_score: float  # 0-100
    criticality_score: float     # 0-100
    impact_categories: List[ImpactCategory]
    response_deadline: str
    escalation_required: bool
    automated_response: bool
    manual_review_required: bool
    justification: str
    recommended_actions: List[str]
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "priority": self.priority.value,
            "priority_score": self.priority_score,
            "impact_score": self.impact_score,
            "urgency_score": self.urgency_score,
            "exploitability_score": self.exploitability_score,
            "criticality_score": self.criticality_score,
            "impact_categories": [c.value for c in self.impact_categories],
            "response_deadline": self.response_deadline,
            "escalation_required": self.escalation_required,
            "automated_response": self.automated_response,
            "manual_review_required": self.manual_review_required,
            "justification": self.justification,
            "recommended_actions": self.recommended_actions,
            "timestamp": self.timestamp
        }


class ImpactAssessor:
    """
    Assesses potential impact of threats on system and business operations.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.ImpactAssessor')
        
        # Threat impact mappings
        self.threat_impacts: Dict[str, Dict[str, Any]] = {
            # Critical threats - immediate system compromise
            "RANSOMWARE_DETECTED": {
                "base_impact": 95,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.FINANCIAL_LOSS, 
                              ImpactCategory.SERVICE_DISRUPTION],
                "data_risk": "HIGH",
                "recovery_difficulty": "VERY_HIGH"
            },
            "RANSOMWARE_ACTIVITY": {
                "base_impact": 100,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.FINANCIAL_LOSS,
                              ImpactCategory.SERVICE_DISRUPTION],
                "data_risk": "CRITICAL",
                "recovery_difficulty": "EXTREME"
            },
            "ROOTKIT_DETECTED": {
                "base_impact": 90,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.PERSISTENCE,
                              ImpactCategory.LATERAL_MOVEMENT],
                "data_risk": "HIGH",
                "recovery_difficulty": "VERY_HIGH"
            },
            "BACKDOOR_DETECTED": {
                "base_impact": 92,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.PERSISTENCE,
                              ImpactCategory.LATERAL_MOVEMENT],
                "data_risk": "HIGH",
                "recovery_difficulty": "HIGH"
            },
            "ZERO_DAY_EXPLOIT_INDICATOR": {
                "base_impact": 98,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.LATERAL_MOVEMENT],
                "data_risk": "CRITICAL",
                "recovery_difficulty": "EXTREME"
            },
            
            # High threats - significant compromise potential
            "TROJAN_DETECTED": {
                "base_impact": 85,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.DATA_BREACH],
                "data_risk": "HIGH",
                "recovery_difficulty": "HIGH"
            },
            "SPYWARE_DETECTED": {
                "base_impact": 80,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.REPUTATION_DAMAGE],
                "data_risk": "HIGH",
                "recovery_difficulty": "MEDIUM"
            },
            "INFOSTEALER_DETECTED": {
                "base_impact": 88,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.FINANCIAL_LOSS],
                "data_risk": "CRITICAL",
                "recovery_difficulty": "HIGH"
            },
            "FILELESS_MALWARE_DETECTED": {
                "base_impact": 85,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.PERSISTENCE],
                "data_risk": "HIGH",
                "recovery_difficulty": "HIGH"
            },
            "PROCESS_INJECTION_DETECTED": {
                "base_impact": 82,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.PERSISTENCE],
                "data_risk": "MEDIUM",
                "recovery_difficulty": "MEDIUM"
            },
            "BOTNET_INFECTION_INDICATOR": {
                "base_impact": 78,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE, ImpactCategory.REPUTATION_DAMAGE],
                "data_risk": "MEDIUM",
                "recovery_difficulty": "MEDIUM"
            },
            "DATA_EXFILTRATION_INDICATOR": {
                "base_impact": 90,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.COMPLIANCE_VIOLATION],
                "data_risk": "CRITICAL",
                "recovery_difficulty": "HIGH"
            },
            "FORMJACKING_DETECTED": {
                "base_impact": 85,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.FINANCIAL_LOSS],
                "data_risk": "HIGH",
                "recovery_difficulty": "MEDIUM"
            },
            
            # Medium threats - moderate impact
            "CRYPTOMINER_DETECTED": {
                "base_impact": 45,
                "categories": [ImpactCategory.SERVICE_DISRUPTION],
                "data_risk": "LOW",
                "recovery_difficulty": "LOW"
            },
            "ADWARE_DETECTED": {
                "base_impact": 30,
                "categories": [ImpactCategory.REPUTATION_DAMAGE],
                "data_risk": "LOW",
                "recovery_difficulty": "LOW"
            },
            "PHISHING_INDICATOR": {
                "base_impact": 60,
                "categories": [ImpactCategory.DATA_BREACH, ImpactCategory.FINANCIAL_LOSS],
                "data_risk": "MEDIUM",
                "recovery_difficulty": "LOW"
            },
            "BRUTE_FORCE_ATTACK": {
                "base_impact": 65,
                "categories": [ImpactCategory.SYSTEM_COMPROMISE],
                "data_risk": "MEDIUM",
                "recovery_difficulty": "LOW"
            },
            "DDOS_ATTACK_INDICATOR": {
                "base_impact": 70,
                "categories": [ImpactCategory.SERVICE_DISRUPTION],
                "data_risk": "LOW",
                "recovery_difficulty": "LOW"
            },
            
            # Low threats - minimal immediate impact
            "ANOMALY": {
                "base_impact": 25,
                "categories": [],
                "data_risk": "UNKNOWN",
                "recovery_difficulty": "LOW"
            },
            "INFOSTEALER_INDICATOR": {
                "base_impact": 55,
                "categories": [ImpactCategory.DATA_BREACH],
                "data_risk": "MEDIUM",
                "recovery_difficulty": "LOW"
            }
        }

    def assess_impact(self, threat: Dict[str, Any], 
                      system_context: Dict[str, Any]) -> Tuple[float, List[ImpactCategory]]:
        """
        Assess potential impact of a threat.
        
        Returns:
            Tuple of (impact_score, impact_categories)
        """
        threat_type = threat.get('type', 'UNKNOWN')
        
        # Get base impact from threat type
        impact_info = self.threat_impacts.get(threat_type, {
            "base_impact": 50,
            "categories": [],
            "data_risk": "MEDIUM",
            "recovery_difficulty": "MEDIUM"
        })
        
        base_score = impact_info['base_impact']
        categories = impact_info['categories'].copy()
        
        # Adjust based on confidence
        confidence = threat.get('confidence', 50)
        confidence_multiplier = confidence / 100.0
        adjusted_score = base_score * confidence_multiplier
        
        # Adjust based on system context
        context_adjustment = self._calculate_context_adjustment(threat, system_context)
        final_score = min(100, adjusted_score + context_adjustment)
        
        # Add context-based categories
        if self._affects_sensitive_data(threat, system_context):
            if ImpactCategory.DATA_BREACH not in categories:
                categories.append(ImpactCategory.DATA_BREACH)
            final_score = min(100, final_score + 10)
        
        if self._enables_lateral_movement(threat):
            if ImpactCategory.LATERAL_MOVEMENT not in categories:
                categories.append(ImpactCategory.LATERAL_MOVEMENT)
            final_score = min(100, final_score + 8)
        
        return round(final_score, 2), categories

    def _calculate_context_adjustment(self, threat: Dict[str, Any],
                                       system_context: Dict[str, Any]) -> float:
        """Calculate impact adjustment based on system context"""
        adjustment = 0.0
        
        # Check if system is critical (server, domain controller, etc.)
        hostname = system_context.get('hostname', '').lower()
        critical_systems = ['server', 'dc-', 'domain', 'database', 'db-', 'mail', 'file']
        if any(critical in hostname for critical in critical_systems):
            adjustment += 15
        
        # Check if system has high privileges
        processes = system_context.get('processes', [])
        admin_processes = [p for p in processes if p.get('username', '').lower() in ['system', 'administrator', 'admin']]
        if admin_processes:
            adjustment += 10
        
        # Check if threat targets critical processes
        target_pids = threat.get('target_pids', [])
        for pid in target_pids:
            proc = next((p for p in processes if p.get('pid') == pid), None)
            if proc:
                proc_name = (proc.get('name') or '').lower()
                critical_procs = ['lsass', 'csrss', 'winlogon', 'services', 'svchost']
                if any(cp in proc_name for cp in critical_procs):
                    adjustment += 20
                    break
        
        return adjustment

    def _affects_sensitive_data(self, threat: Dict[str, Any],
                                 system_context: Dict[str, Any]) -> bool:
        """Check if threat affects sensitive data"""
        threat_type = threat.get('type', '')
        
        # Threats that directly access data
        data_threats = [
            'INFOSTEALER', 'SPYWARE', 'KEYLOG', 'DATA_EXFILTRATION',
            'FORMJACKING', 'SESSION_HIJACKING', 'PACKET_SNIFFING'
        ]
        
        return any(dt in threat_type for dt in data_threats)

    def _enables_lateral_movement(self, threat: Dict[str, Any]) -> bool:
        """Check if threat enables lateral movement"""
        threat_type = threat.get('type', '')
        
        # Threats that enable lateral movement
        lateral_threats = [
            'BACKDOOR', 'ROOTKIT', 'BOTNET', 'CREDENTIAL',
            'BRUTE_FORCE', 'PASS_THE_HASH', 'PASS_THE_TICKET'
        ]
        
        return any(lt in threat_type for lt in lateral_threats)


class UrgencyAssessor:
    """
    Assesses urgency of threat response based on attack progression
    and time sensitivity.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.UrgencyAssessor')
        
        # Threat urgency mappings (how quickly response is needed)
        self.threat_urgency: Dict[str, float] = {
            # Immediate response required
            "RANSOMWARE_ACTIVITY": 100,
            "RANSOMWARE_DETECTED": 95,
            "ZERO_DAY_EXPLOIT_INDICATOR": 98,
            "DATA_EXFILTRATION_INDICATOR": 90,
            "WIPER_MALWARE_DETECTED": 100,
            "DOUBLE_EXTORTION_RANSOMWARE": 98,
            
            # Response within minutes
            "ROOTKIT_DETECTED": 85,
            "BACKDOOR_DETECTED": 88,
            "FILELESS_MALWARE_DETECTED": 82,
            "PROCESS_INJECTION_DETECTED": 80,
            "BOTNET_INFECTION_INDICATOR": 78,
            "INFOSTEALER_DETECTED": 85,
            
            # Response within hours
            "TROJAN_DETECTED": 75,
            "SPYWARE_DETECTED": 70,
            "FORMJACKING_DETECTED": 72,
            "BRUTE_FORCE_ATTACK": 65,
            "DDOS_ATTACK_INDICATOR": 68,
            
            # Response within days
            "CRYPTOMINER_DETECTED": 45,
            "ADWARE_DETECTED": 30,
            "PHISHING_INDICATOR": 55,
            "ANOMALY": 25,
            
            # Informational
            "INFOSTEALER_INDICATOR": 50,
            "BAITING_ATTACK_INDICATOR": 40
        }

    def assess_urgency(self, threat: Dict[str, Any],
                       system_state: Dict[str, Any]) -> Tuple[float, str]:
        """
        Assess urgency of threat response.
        
        Returns:
            Tuple of (urgency_score, response_deadline)
        """
        threat_type = threat.get('type', 'UNKNOWN')
        
        # Get base urgency
        base_urgency = self.threat_urgency.get(threat_type, 50)
        
        # Adjust based on attack progression indicators
        progression_adjustment = self._assess_attack_progression(threat, system_state)
        urgency_score = min(100, base_urgency + progression_adjustment)
        
        # Calculate response deadline
        deadline = self._calculate_deadline(urgency_score)
        
        return round(urgency_score, 2), deadline

    def _assess_attack_progression(self, threat: Dict[str, Any],
                                    system_state: Dict[str, Any]) -> float:
        """Assess how far the attack has progressed"""
        adjustment = 0.0
        
        # Check for multiple related threats (attack campaign)
        threat_type = threat.get('type', '')
        related_threats = threat.get('related_threats', [])
        if related_threats:
            adjustment += min(20, len(related_threats) * 5)
        
        # Check for active data exfiltration
        if 'EXFILTRATION' in threat_type:
            network = system_state.get('network', {})
            bytes_sent = network.get('bytes_sent', 0)
            if bytes_sent > 100_000_000:  # > 100MB sent
                adjustment += 15
        
        # Check for active encryption (ransomware)
        if 'RANSOMWARE' in threat_type:
            disk_percent = system_state.get('disk_percent', 0)
            if disk_percent > 90:
                adjustment += 20
        
        # Check for privilege escalation
        if self._indicates_privilege_escalation(threat):
            adjustment += 12
        
        return adjustment

    def _indicates_privilege_escalation(self, threat: Dict[str, Any]) -> bool:
        """Check if threat indicates privilege escalation"""
        threat_type = threat.get('type', '')
        description = threat.get('description', '').lower()
        
        priv_indicators = ['privilege', 'escalation', 'admin', 'system', 'root', 'sudo']
        return any(ind in threat_type.lower() or ind in description for ind in priv_indicators)

    def _calculate_deadline(self, urgency_score: float) -> str:
        """Calculate response deadline based on urgency"""
        now = datetime.datetime.utcnow()
        
        if urgency_score >= 90:
            deadline = now + datetime.timedelta(minutes=15)
            return f"IMMEDIATE - by {deadline.strftime('%H:%M UTC')}"
        elif urgency_score >= 80:
            deadline = now + datetime.timedelta(hours=1)
            return f"Within 1 hour - by {deadline.strftime('%H:%M UTC')}"
        elif urgency_score >= 70:
            deadline = now + datetime.timedelta(hours=4)
            return f"Within 4 hours - by {deadline.strftime('%H:%M UTC')}"
        elif urgency_score >= 60:
            deadline = now + datetime.timedelta(hours=12)
            return f"Within 12 hours - by {deadline.strftime('%H:%M UTC')}"
        elif urgency_score >= 40:
            deadline = now + datetime.timedelta(days=1)
            return f"Within 24 hours - by {deadline.strftime('%Y-%m-%d')}"
        else:
            deadline = now + datetime.timedelta(days=7)
            return f"Within 1 week - by {deadline.strftime('%Y-%m-%d')}"


class ExploitabilityAssessor:
    """
    Assesses how easily a threat can be exploited by attackers.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.ExploitabilityAssessor')

    def assess_exploitability(self, threat: Dict[str, Any],
                               system_context: Dict[str, Any]) -> float:
        """
        Assess exploitability of threat.
        
        Returns:
            Exploitability score (0-100)
        """
        score = 50.0  # Default medium exploitability
        
        threat_type = threat.get('type', '')
        
        # Network-accessible threats are more exploitable
        if self._is_network_accessible(threat):
            score += 20
        
        # Threats with known exploits are more exploitable
        if self._has_known_exploit(threat_type):
            score += 15
        
        # Threats requiring no user interaction are more exploitable
        if self._requires_no_interaction(threat_type):
            score += 15
        
        # Threats with public tools are more exploitable
        if self._has_public_tools(threat_type):
            score += 10
        
        # Adjust based on system exposure
        exposure_adjustment = self._assess_system_exposure(system_context)
        score += exposure_adjustment
        
        return min(100, max(0, score))

    def _is_network_accessible(self, threat: Dict[str, Any]) -> bool:
        """Check if threat is network-accessible"""
        threat_type = threat.get('type', '')
        network_threats = [
            'DDOS', 'SSRF', 'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION',
            'BRUTE_FORCE', 'BACKDOOR', 'BOTNET'
        ]
        return any(nt in threat_type for nt in network_threats)

    def _has_known_exploit(self, threat_type: str) -> bool:
        """Check if threat has known public exploits"""
        known_exploit_threats = [
            'RANSOMWARE', 'TROJAN', 'ROOTKIT', 'ZERO_DAY',
            'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION'
        ]
        return any(ke in threat_type for ke in known_exploit_threats)

    def _requires_no_interaction(self, threat_type: str) -> bool:
        """Check if threat requires no user interaction"""
        no_interaction_threats = [
            'RANSOMWARE', 'WORM', 'BOTNET', 'DDOS',
            'SQL_INJECTION', 'COMMAND_INJECTION', 'SSRF'
        ]
        return any(ni in threat_type for ni in no_interaction_threats)

    def _has_public_tools(self, threat_type: str) -> bool:
        """Check if threat has publicly available tools"""
        public_tool_threats = [
            'RANSOMWARE', 'TROJAN', 'DDOS', 'BRUTE_FORCE',
            'SQL_INJECTION', 'XSS'
        ]
        return any(pt in threat_type for pt in public_tool_threats)

    def _assess_system_exposure(self, system_context: Dict[str, Any]) -> float:
        """Assess system exposure level"""
        adjustment = 0.0
        
        # Check for open ports
        security = system_context.get('security', {})
        open_ports = security.get('open_ports', [])
        
        # Common service ports increase exposure
        exposed_ports = [80, 443, 22, 3389, 445, 1433, 3306, 5432]
        exposed_count = sum(1 for port in open_ports if port in exposed_ports)
        adjustment += min(15, exposed_count * 3)
        
        # Check for public IP (simplified)
        network = system_context.get('network', {})
        connections = network.get('connections', [])
        has_public_connections = any(
            not ((conn.get('remote_ip') or '').startswith('192.168.') or
                 (conn.get('remote_ip') or '').startswith('10.') or
                 (conn.get('remote_ip') or '').startswith('172.') or
                 (conn.get('remote_ip') or '').startswith('127.') or
                 (conn.get('remote_ip') or '') == '')
            for conn in connections
        )
        
        if has_public_connections:
            adjustment += 10
        
        return adjustment


class CriticalityAssessor:
    """
    Assesses criticality of affected assets and resources.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.CriticalityAssessor')
        
        # Critical process names
        self.critical_processes = {
            'lsass.exe': 100,      # Authentication
            'csrss.exe': 95,       # Client/Server Runtime
            'winlogon.exe': 90,    # Logon process
            'services.exe': 85,    # Service Control Manager
            'svchost.exe': 80,     # Service Host
            'system': 100,         # System kernel
            'smss.exe': 90,        # Session Manager
            'wininit.exe': 85,     # Windows Init
            'lsaiso.exe': 95,      # Credential Guard
        }
        
        # Critical file paths
        self.critical_paths = [
            'windows\\system32',
            'windows\\syswow64',
            'program files',
            'boot',
            'efi'
        ]

    def assess_criticality(self, threat: Dict[str, Any],
                            system_context: Dict[str, Any]) -> float:
        """
        Assess criticality of affected assets.
        
        Returns:
            Criticality score (0-100)
        """
        score = 50.0  # Default medium criticality
        
        processes = system_context.get('processes', [])
        target_pids = threat.get('target_pids', [])
        
        # Check if critical processes are affected
        for pid in target_pids:
            proc = next((p for p in processes if p.get('pid') == pid), None)
            if proc:
                proc_name = (proc.get('name') or '').lower()
                proc_criticality = self.critical_processes.get(proc_name, 0)
                score = max(score, proc_criticality)
        
        # Check if critical paths are affected
        exe_path = threat.get('exe_path', '').lower()
        for critical_path in self.critical_paths:
            if critical_path in exe_path:
                score = max(score, 85)
                break
        
        # Check system role
        hostname = system_context.get('hostname', '').lower()
        if any(role in hostname for role in ['server', 'dc', 'domain', 'database']):
            score = max(score, 90)
        
        return min(100, score)


class ThreatPrioritizer:
    """
    Main threat prioritization engine that coordinates all assessment components.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger('SENTINEL.ThreatPrioritizer')
        
        # Initialize assessors
        self.impact_assessor = ImpactAssessor()
        self.urgency_assessor = UrgencyAssessor()
        self.exploitability_assessor = ExploitabilityAssessor()
        self.criticality_assessor = CriticalityAssessor()
        
        # Priority thresholds
        self.priority_thresholds = {
            Priority.P0_CRITICAL: 90,
            Priority.P1_HIGH: 75,
            Priority.P2_MEDIUM: 50,
            Priority.P3_LOW: 25,
            Priority.P4_INFO: 0
        }
        
        # Statistics
        self.stats = {
            'total_prioritized': 0,
            'by_priority': {p.value: 0 for p in Priority},
            'escalations': 0
        }
        
        self.logger.info("ThreatPrioritizer initialized")

    def prioritize_threats(self, threats: List[Dict[str, Any]],
                           system_context: Dict[str, Any]) -> List[ThreatPriority]:
        """
        Prioritize a list of threats.
        
        Args:
            threats: List of detected threats
            system_context: Current system context
            
        Returns:
            List of ThreatPriority objects sorted by priority
        """
        if not threats:
            return []
        
        priorities = []
        
        for threat in threats:
            priority = self._prioritize_single_threat(threat, system_context)
            priorities.append(priority)
            
            # Update statistics
            self.stats['total_prioritized'] += 1
            self.stats['by_priority'][priority.priority.value] += 1
            if priority.escalation_required:
                self.stats['escalations'] += 1
        
        # Sort by priority score (highest first)
        priorities.sort(key=lambda p: p.priority_score, reverse=True)
        
        self.logger.info(
            f"Prioritized {len(threats)} threats: "
            f"{self.stats['by_priority'][Priority.P0_CRITICAL.value]} P0, "
            f"{self.stats['by_priority'][Priority.P1_HIGH.value]} P1, "
            f"{self.stats['by_priority'][Priority.P2_MEDIUM.value]} P2"
        )
        
        return priorities

    def _prioritize_single_threat(self, threat: Dict[str, Any],
                                   system_context: Dict[str, Any]) -> ThreatPriority:
        """Prioritize a single threat"""
        threat_type = threat.get('type', 'UNKNOWN')
        threat_id = threat.get('id', f"threat_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
        
        # Assess all dimensions
        impact_score, impact_categories = self.impact_assessor.assess_impact(
            threat, system_context
        )
        urgency_score, deadline = self.urgency_assessor.assess_urgency(
            threat, system_context
        )
        exploitability_score = self.exploitability_assessor.assess_exploitability(
            threat, system_context
        )
        criticality_score = self.criticality_assessor.assess_criticality(
            threat, system_context
        )
        
        # Calculate overall priority score
        priority_score = self._calculate_priority_score(
            impact_score, urgency_score, exploitability_score, criticality_score
        )
        
        # Determine priority level
        priority_level = self._determine_priority_level(priority_score)
        
        # Determine if escalation is required
        escalation_required = (
            priority_level in [Priority.P0_CRITICAL, Priority.P1_HIGH] or
            impact_score >= 90 or
            any(cat in [ImpactCategory.DATA_BREACH, ImpactCategory.SYSTEM_COMPROMISE] 
                for cat in impact_categories)
        )
        
        # Determine if automated response is appropriate
        automated_response = (
            priority_level in [Priority.P0_CRITICAL, Priority.P1_HIGH] and
            threat.get('confidence', 0) >= 80
        )
        
        # Determine if manual review is required
        manual_review_required = (
            priority_level == Priority.P0_CRITICAL or
            threat.get('confidence', 0) < 70 or
            'ZERO_DAY' in threat_type
        )
        
        # Generate justification
        justification = self._generate_justification(
            threat_type, priority_level, impact_score, urgency_score,
            exploitability_score, criticality_score, impact_categories
        )
        
        # Generate recommended actions
        recommended_actions = self._generate_recommended_actions(
            threat, priority_level, impact_categories
        )
        
        return ThreatPriority(
            threat_id=threat_id,
            threat_type=threat_type,
            priority=priority_level,
            priority_score=priority_score,
            impact_score=impact_score,
            urgency_score=urgency_score,
            exploitability_score=exploitability_score,
            criticality_score=criticality_score,
            impact_categories=impact_categories,
            response_deadline=deadline,
            escalation_required=escalation_required,
            automated_response=automated_response,
            manual_review_required=manual_review_required,
            justification=justification,
            recommended_actions=recommended_actions
        )

    def _calculate_priority_score(self, impact: float, urgency: float,
                                   exploitability: float, criticality: float) -> float:
        """Calculate overall priority score using weighted average"""
        # Weights for each dimension
        weights = {
            'impact': 0.35,
            'urgency': 0.30,
            'exploitability': 0.20,
            'criticality': 0.15
        }
        
        score = (
            impact * weights['impact'] +
            urgency * weights['urgency'] +
            exploitability * weights['exploitability'] +
            criticality * weights['criticality']
        )
        
        return round(score, 2)

    def _determine_priority_level(self, priority_score: float) -> Priority:
        """Determine priority level from score"""
        for priority, threshold in sorted(self.priority_thresholds.items(),
                                          key=lambda x: x[1], reverse=True):
            if priority_score >= threshold:
                return priority
        return Priority.P4_INFO

    def _generate_justification(self, threat_type: str, priority: Priority,
                                 impact: float, urgency: float,
                                 exploitability: float, criticality: float,
                                 categories: List[ImpactCategory]) -> str:
        """Generate human-readable justification for priority"""
        parts = [
            f"Threat '{threat_type}' classified as {priority.value}.",
            f"Impact: {impact:.0f}/100, Urgency: {urgency:.0f}/100, "
            f"Exploitability: {exploitability:.0f}/100, Criticality: {criticality:.0f}/100."
        ]
        
        if categories:
            cat_names = [c.value.replace('_', ' ').title() for c in categories]
            parts.append(f"Potential impacts: {', '.join(cat_names)}.")
        
        if priority == Priority.P0_CRITICAL:
            parts.append("IMMEDIATE ACTION REQUIRED to prevent system compromise.")
        elif priority == Priority.P1_HIGH:
            parts.append("High priority - respond within 1 hour.")
        
        return " ".join(parts)

    def _generate_recommended_actions(self, threat: Dict[str, Any],
                                       priority: Priority,
                                       categories: List[ImpactCategory]) -> List[str]:
        """Generate recommended actions based on threat and priority"""
        actions = []
        
        # Priority-based actions
        if priority == Priority.P0_CRITICAL:
            actions.extend([
                "IMMEDIATELY isolate affected systems from network",
                "Activate incident response team",
                "Preserve forensic evidence",
                "Notify management and stakeholders"
            ])
        elif priority == Priority.P1_HIGH:
            actions.extend([
                "Isolate affected systems within 1 hour",
                "Begin incident investigation",
                "Implement containment measures"
            ])
        
        # Category-based actions
        if ImpactCategory.DATA_BREACH in categories:
            actions.extend([
                "Identify compromised data",
                "Notify affected parties if required",
                "Review data access logs"
            ])
        
        if ImpactCategory.SYSTEM_COMPROMISE in categories:
            actions.extend([
                "Check for persistence mechanisms",
                "Review system integrity",
                "Consider system rebuild if necessary"
            ])
        
        if ImpactCategory.LATERAL_MOVEMENT in categories:
            actions.extend([
                "Check other systems for compromise",
                "Review network segmentation",
                "Monitor for suspicious authentication"
            ])
        
        # Threat-specific actions
        threat_type = threat.get('type', '')
        if 'RANSOMWARE' in threat_type:
            actions.extend([
                "DO NOT pay ransom",
                "Check for decryptor tools",
                "Restore from clean backups"
            ])
        
        if 'EXFILTRATION' in threat_type:
            actions.extend([
                "Block outbound connections to suspicious IPs",
                "Review what data may have been stolen",
                "Enable DLP controls"
            ])
        
        return actions[:10]  # Limit to top 10 actions

    def get_statistics(self) -> Dict[str, Any]:
        """Get prioritization statistics"""
        return self.stats

    def get_priority_summary(self, priorities: List[ThreatPriority]) -> Dict[str, Any]:
        """Get summary of prioritized threats"""
        if not priorities:
            return {
                "total_threats": 0,
                "by_priority": {},
                "requires_immediate_action": 0,
                "requires_escalation": 0
            }
        
        by_priority = defaultdict(int)
        immediate_action = 0
        escalations = 0
        
        for p in priorities:
            by_priority[p.priority.value] += 1
            if p.priority in [Priority.P0_CRITICAL, Priority.P1_HIGH]:
                immediate_action += 1
            if p.escalation_required:
                escalations += 1
        
        return {
            "total_threats": len(priorities),
            "by_priority": dict(by_priority),
            "requires_immediate_action": immediate_action,
            "requires_escalation": escalations,
            "highest_priority": priorities[0].priority.value if priorities else None,
            "highest_priority_threat": priorities[0].threat_type if priorities else None
        }


if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  SENTINEL - Intelligent Threat Prioritization Framework")
    print("=" * 70)
    print()
    print("Priority Levels:")
    print("  P0_CRITICAL - Immediate action required (score ≥ 90)")
    print("  P1_HIGH     - Action within 1 hour (score ≥ 75)")
    print("  P2_MEDIUM   - Action within 24 hours (score ≥ 50)")
    print("  P3_LOW      - Action within 1 week (score ≥ 25)")
    print("  P4_INFO     - Informational only (score < 25)")
    print()
    print("Assessment Dimensions:")
    print("  - Impact (35%): Potential damage to system/data")
    print("  - Urgency (30%): Time sensitivity of response")
    print("  - Exploitability (20%): Ease of exploitation")
    print("  - Criticality (15%): Importance of affected assets")
    print()
    print("=" * 70)
