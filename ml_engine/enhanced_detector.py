"""
SENTINEL - Enhanced Threat Detection System
============================================
Comprehensive integration of all detection, filtering, and prioritization components.
This is the main entry point for the enhanced threat detection system.

Features:
- Multi-layer threat detection (Rule-based + ML anomaly)
- Advanced false positive filtering
- Intelligent threat prioritization
- Adaptive confidence scoring
- Real-time threat correlation
- Automated response optimization
- Comprehensive reporting

Author: SENTINEL Development Team
Version: 2.0.0
"""

import logging
import datetime
import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

# Import SENTINEL components
from ml_engine.detector import (
    SentinelDetector, RuleEngine, AnomalyDetector, 
    ThreatClassifier, AutoResponseEngine, AutoAction
)
from ml_engine.false_positive_filter import FalsePositiveFilter, FilterResult
from ml_engine.threat_prioritizer import ThreatPrioritizer, ThreatPriority, Priority

logger = logging.getLogger('SENTINEL.EnhancedDetector')


@dataclass
class DetectionResult:
    """Complete detection result with all metadata"""
    threats: List[Dict[str, Any]]
    priorities: List[ThreatPriority]
    filter_results: List[FilterResult]
    anomaly_score: float
    anomaly_reason: str
    system_status: str
    detection_timestamp: str
    processing_time_ms: float
    statistics: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "threats": self.threats,
            "priorities": [p.to_dict() for p in self.priorities],
            "filter_results": [f.to_dict() for f in self.filter_results],
            "anomaly_score": self.anomaly_score,
            "anomaly_reason": self.anomaly_reason,
            "system_status": self.system_status,
            "detection_timestamp": self.detection_timestamp,
            "processing_time_ms": self.processing_time_ms,
            "statistics": self.statistics
        }


class AdaptiveConfidenceScorer:
    """
    Adaptive confidence scoring mechanism that adjusts threat confidence
    based on multiple factors and historical accuracy.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.AdaptiveConfidenceScorer')
        
        # Historical accuracy tracking
        self.true_positives: int = 0
        self.false_positives: int = 0
        self.true_negatives: int = 0
        self.false_negatives: int = 0
        
        # Confidence adjustment factors
        self.adjustment_factors = {
            'signature_match': 1.2,      # Boost for signature matches
            'behavioral_anomaly': 1.1,   # Boost for behavioral anomalies
            'multiple_indicators': 1.3,  # Boost for multiple indicators
            'known_safe': 0.3,           # Reduce for known safe
            'whitelisted': 0.2,          # Reduce for whitelisted
            'low_activity': 0.8,         # Reduce for low activity
            'high_activity': 1.1,        # Boost for high activity
            'context_match': 1.15,       # Boost for context match
            'historical_accuracy': 1.0   # Based on past performance
        }
        
        # Threat type base confidence
        self.base_confidence = {
            'RANSOMWARE': 85,
            'TROJAN': 80,
            'SPYWARE': 75,
            'ROOTKIT': 85,
            'BACKDOOR': 82,
            'INFOSTEALER': 78,
            'FILELESS_MALWARE': 75,
            'ZERO_DAY': 70,
            'BOTNET': 72,
            'DDOS': 68,
            'SQL_INJECTION': 75,
            'XSS': 70,
            'COMMAND_INJECTION': 78,
            'PHISHING': 65,
            'BRUTE_FORCE': 70,
            'ANOMALY': 50
        }

    def calculate_confidence(self, threat: Dict[str, Any],
                             context: Dict[str, Any]) -> float:
        """
        Calculate adaptive confidence score for a threat.
        
        Args:
            threat: Threat dictionary
            context: System context and metadata
            
        Returns:
            Adjusted confidence score (0-100)
        """
        threat_type = threat.get('type', 'UNKNOWN')
        
        # Get base confidence
        base = self.base_confidence.get(threat_type, 60)
        
        # Apply adjustment factors
        adjustments = []
        
        # Signature match boost
        if threat.get('signature_matched', False):
            adjustments.append(self.adjustment_factors['signature_match'])
        
        # Behavioral anomaly boost
        if threat.get('anomaly_score', 0) > 0.7:
            adjustments.append(self.adjustment_factors['behavioral_anomaly'])
        
        # Multiple indicators boost
        related = threat.get('related_threats', [])
        if len(related) > 0:
            adjustments.append(self.adjustment_factors['multiple_indicators'])
        
        # Known safe reduction
        if threat.get('is_known_safe', False):
            adjustments.append(self.adjustment_factors['known_safe'])
        
        # Whitelisted reduction
        if threat.get('filter_validated', False):
            adjustments.append(self.adjustment_factors['whitelisted'])
        
        # Activity level adjustment
        processes = context.get('processes', [])
        if len(processes) > 100:
            adjustments.append(self.adjustment_factors['high_activity'])
        elif len(processes) < 20:
            adjustments.append(self.adjustment_factors['low_activity'])
        
        # Context match boost
        if threat.get('context_validated', False):
            adjustments.append(self.adjustment_factors['context_match'])
        
        # Historical accuracy adjustment
        accuracy = self._get_historical_accuracy()
        adjustments.append(accuracy)
        
        # Calculate final confidence
        if adjustments:
            avg_adjustment = sum(adjustments) / len(adjustments)
            adjusted = base * avg_adjustment
        else:
            adjusted = base
        
        # Clamp to 0-100
        return min(100, max(0, round(adjusted, 2)))

    def _get_historical_accuracy(self) -> float:
        """Get historical accuracy multiplier"""
        total = self.true_positives + self.false_positives
        if total == 0:
            return 1.0  # No history, use neutral
        
        accuracy = self.true_positives / total
        
        # Convert to multiplier: 100% accuracy = 1.2x, 50% = 1.0x, 0% = 0.8x
        return 0.8 + (accuracy * 0.4)

    def update_accuracy(self, was_true_positive: bool):
        """Update historical accuracy based on feedback"""
        if was_true_positive:
            self.true_positives += 1
        else:
            self.false_positives += 1

    def get_accuracy_stats(self) -> Dict[str, Any]:
        """Get accuracy statistics"""
        total = self.true_positives + self.false_positives
        return {
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'accuracy': self.true_positives / max(total, 1),
            'total_assessments': total
        }


class ThreatIntelligence:
    """
    Real-time threat intelligence integration.
    Provides context about known threats, IOCs, and attack patterns.
    """

    def __init__(self, intel_file: str = None):
        self.logger = logging.getLogger('SENTINEL.ThreatIntelligence')
        
        self.intel_file = intel_file or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'threat_intelligence.json'
        )
        
        # Known threat indicators
        self.known_threats: Dict[str, Dict[str, Any]] = {}
        self.iocs: Dict[str, List[str]] = {
            'malicious_ips': [],
            'malicious_domains': [],
            'malicious_hashes': [],
            'malicious_processes': []
        }
        
        # Load threat intelligence
        self._load_intelligence()
        
        self.logger.info(f"ThreatIntelligence initialized with {len(self.known_threats)} known threats")

    def _load_intelligence(self):
        """Load threat intelligence from file"""
        try:
            if os.path.exists(self.intel_file):
                with open(self.intel_file, 'r') as f:
                    data = json.load(f)
                    
                self.known_threats = data.get('known_threats', {})
                self.iocs = data.get('iocs', self.iocs)
                
                self.logger.info(f"Loaded threat intelligence from {self.intel_file}")
        except Exception as e:
            self.logger.warning(f"Could not load threat intelligence: {e}")

    def check_threat(self, threat: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if threat matches known intelligence.
        
        Returns:
            Tuple of (is_known_threat, intelligence_data)
        """
        threat_type = threat.get('type', '')
        
        # Check against known threats
        if threat_type in self.known_threats:
            return True, self.known_threats[threat_type]
        
        # Check IOCs
        target_ips = threat.get('target_ips', [])
        for ip in target_ips:
            if ip in self.iocs['malicious_ips']:
                return True, {'ioc_match': 'malicious_ip', 'ip': ip}
        
        # Check process hashes
        exe_path = threat.get('exe_path', '')
        if exe_path:
            # In production, would hash the file and check
            pass
        
        return False, {}

    def get_threat_info(self, threat_type: str) -> Dict[str, Any]:
        """Get detailed information about a threat type"""
        return self.known_threats.get(threat_type, {})

    def add_ioc(self, ioc_type: str, value: str):
        """Add an indicator of compromise"""
        if ioc_type in self.iocs:
            self.iocs[ioc_type].append(value)
            self.logger.info(f"Added {ioc_type}: {value}")


class ResponseOptimizer:
    """
    Optimizes automated responses based on threat context and system state.
    Ensures responses are proportionate and effective.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.ResponseOptimizer')
        
        # Response effectiveness tracking
        self.response_history: List[Dict[str, Any]] = []
        
        # Response rules
        self.response_rules = {
            'RANSOMWARE': {
                'immediate': ['EMERGENCY_SHUTDOWN', 'ISOLATE_AND_ALERT'],
                'follow_up': ['QUARANTINE_FILE', 'BLOCK_IP'],
                'escalate': True
            },
            'BACKDOOR': {
                'immediate': ['SUSPEND_PROCESS', 'BLOCK_IP'],
                'follow_up': ['ISOLATE_AND_ALERT'],
                'escalate': True
            },
            'INFOSTEALER': {
                'immediate': ['SUSPEND_PROCESS', 'RESET_SESSION'],
                'follow_up': ['BLOCK_IP', 'CLEAR_CACHE'],
                'escalate': True
            },
            'DDOS': {
                'immediate': ['BLOCK_IP'],
                'follow_up': ['ALERT_ONLY'],
                'escalate': False
            },
            'CRYPTOMINER': {
                'immediate': ['SUSPEND_PROCESS'],
                'follow_up': ['ALERT_ONLY'],
                'escalate': False
            }
        }

    def optimize_response(self, threat: Dict[str, Any],
                          priority: ThreatPriority,
                          system_state: Dict[str, Any]) -> List[str]:
        """
        Optimize response actions for a threat.
        
        Returns:
            List of optimized response actions
        """
        threat_type = threat.get('type', '')
        
        # Get base response rules
        rules = self.response_rules.get(threat_type, {
            'immediate': ['ALERT_ONLY'],
            'follow_up': [],
            'escalate': False
        })
        
        actions = []
        
        # Add immediate actions based on priority
        if priority.priority in [Priority.P0_CRITICAL, Priority.P1_HIGH]:
            actions.extend(rules['immediate'])
        else:
            # For lower priorities, use less aggressive responses
            if 'EMERGENCY_SHUTDOWN' in rules['immediate']:
                actions.append('ISOLATE_AND_ALERT')
            elif 'SUSPEND_PROCESS' in rules['immediate']:
                actions.append('ALERT_ONLY')
            else:
                actions.extend(rules['immediate'])
        
        # Add follow-up actions if threat is confirmed
        if threat.get('confidence', 0) >= 80:
            actions.extend(rules['follow_up'])
        
        # Optimize based on system state
        actions = self._optimize_for_system(actions, system_state)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_actions = []
        for action in actions:
            if action not in seen:
                seen.add(action)
                unique_actions.append(action)
        
        return unique_actions

    def _optimize_for_system(self, actions: List[str],
                              system_state: Dict[str, Any]) -> List[str]:
        """Optimize actions based on current system state"""
        optimized = []
        
        for action in actions:
            # Don't isolate if already isolated
            if action == 'ISOLATE_AND_ALERT':
                network = system_state.get('network', {})
                if network.get('is_isolated', False):
                    continue
            
            # Don't block IPs that are already blocked
            if action == 'BLOCK_IP':
                # In production, would check firewall rules
                pass
            
            # Don't shutdown during critical operations
            if action == 'EMERGENCY_SHUTDOWN':
                # Check if system is in critical state
                cpu = system_state.get('cpu_percent', 0)
                if cpu > 90:
                    # System is already stressed, shutdown might cause issues
                    optimized.append('ISOLATE_AND_ALERT')
                    continue
            
            optimized.append(action)
        
        return optimized

    def record_response(self, threat_type: str, actions: List[str],
                        success: bool, impact: str):
        """Record response for learning"""
        self.response_history.append({
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'threat_type': threat_type,
            'actions': actions,
            'success': success,
            'impact': impact
        })


class EnhancedThreatDetector:
    """
    Main enhanced threat detection system that integrates all components.
    Provides comprehensive threat detection with minimal false positives.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger('SENTINEL.EnhancedDetector')
        
        # Initialize all components
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector(
            window_size=self.config.get('baseline_window', 100)
        )
        self.classifier = ThreatClassifier()
        self.auto_response = AutoResponseEngine(
            quarantine_dir=self.config.get('quarantine_dir'),
            log_dir=self.config.get('log_dir')
        )
        
        # Enhanced components
        self.fp_filter = FalsePositiveFilter(self.config.get('filter_config'))
        self.prioritizer = ThreatPrioritizer(self.config.get('prioritizer_config'))
        self.confidence_scorer = AdaptiveConfidenceScorer()
        self.threat_intel = ThreatIntelligence(self.config.get('intel_file'))
        self.response_optimizer = ResponseOptimizer()
        
        # State tracking
        self.threat_history: List[Dict] = []
        self.detection_count: int = 0
        self.false_positive_count: int = 0
        
        self.logger.info("Enhanced Threat Detection System initialized")

    def analyze(self, snapshot: Dict[str, Any],
                auto_respond: bool = True) -> DetectionResult:
        """
        Perform comprehensive threat analysis.
        
        Args:
            snapshot: Complete system snapshot
            auto_respond: Whether to execute automated responses
            
        Returns:
            DetectionResult with all analysis data
        """
        start_time = datetime.datetime.utcnow()
        
        try:
            # Extract components from snapshot
            system_state = snapshot.get("system", {})
            processes = snapshot.get("processes", [])
            network = snapshot.get("network", {})
            security = snapshot.get("security", {})
            
            # Step 1: Update ML baseline
            self.anomaly_detector.update_baseline(snapshot)
            
            # Step 2: Run rule-based detection
            rule_threats = self.rule_engine.analyze(snapshot)
            
            # Step 3: Run ML anomaly detection
            anomaly_score, anomaly_reason = self.anomaly_detector.calculate_anomaly_score(snapshot)
            
            # Step 4: Add ML anomaly if significant
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
            
            # Step 5: Apply false positive filtering
            filtered_threats, filter_results = self.fp_filter.filter_threats(
                rule_threats, system_state, processes
            )
            
            # Step 6: Apply adaptive confidence scoring
            for threat in filtered_threats:
                threat['confidence'] = self.confidence_scorer.calculate_confidence(
                    threat, snapshot
                )
            
            # Step 7: Check threat intelligence
            for threat in filtered_threats:
                is_known, intel_data = self.threat_intel.check_threat(threat)
                if is_known:
                    threat['threat_intel_match'] = True
                    threat['intel_data'] = intel_data
                    # Boost confidence for known threats
                    threat['confidence'] = min(100, threat['confidence'] + 10)
            
            # Step 8: Classify threats
            classified = [self.classifier.classify(t) for t in filtered_threats]
            
            # Step 9: Prioritize threats
            priorities = self.prioritizer.prioritize_threats(classified, snapshot)
            
            # Step 10: Optimize and execute responses
            auto_response_results = []
            if auto_respond and priorities:
                for priority in priorities:
                    threat = next(
                        (t for t in classified if t.get('type') == priority.threat_type),
                        None
                    )
                    if threat:
                        # Optimize response
                        optimized_actions = self.response_optimizer.optimize_response(
                            threat, priority, system_state
                        )
                        
                        # Execute each action
                        for action_str in optimized_actions:
                            try:
                                action = AutoAction(action_str)
                                result = self.auto_response.execute(action, threat)
                                auto_response_results.append(result.to_dict())
                                
                                # Record response
                                self.response_optimizer.record_response(
                                    threat.get('type', ''),
                                    [action_str],
                                    result.success,
                                    result.message
                                )
                            except ValueError:
                                self.logger.warning(f"Unknown action: {action_str}")
            
            # Update history
            self.threat_history.extend(classified)
            self.detection_count += 1
            
            # Calculate processing time
            end_time = datetime.datetime.utcnow()
            processing_time = (end_time - start_time).total_seconds() * 1000
            
            # Determine system status
            system_status = self._determine_system_status(priorities, anomaly_score)
            
            # Compile statistics
            statistics = self._compile_statistics(
                rule_threats, filtered_threats, priorities, filter_results
            )
            
            # Log results
            if classified:
                self.logger.info(
                    f"Detection #{self.detection_count}: "
                    f"{len(rule_threats)} raw → {len(filtered_threats)} filtered → "
                    f"{len(classified)} genuine threats"
                )
            
            return DetectionResult(
                threats=classified,
                priorities=priorities,
                filter_results=filter_results,
                anomaly_score=anomaly_score,
                anomaly_reason=anomaly_reason,
                system_status=system_status,
                detection_timestamp=end_time.isoformat(),
                processing_time_ms=processing_time,
                statistics=statistics
            )
            
        except Exception as e:
            self.logger.error(f"Error during threat analysis: {e}", exc_info=True)
            
            return DetectionResult(
                threats=[],
                priorities=[],
                filter_results=[],
                anomaly_score=0.0,
                anomaly_reason=f"Error during analysis: {str(e)}",
                system_status="ERROR",
                detection_timestamp=datetime.datetime.utcnow().isoformat(),
                processing_time_ms=0,
                statistics={'error': str(e)}
            )

    def _determine_system_status(self, priorities: List[ThreatPriority],
                                  anomaly_score: float) -> str:
        """Determine overall system status"""
        if not priorities:
            if anomaly_score > 0.75:
                return "CAUTION"
            return "SAFE"
        
        # Check highest priority
        highest = priorities[0]
        
        if highest.priority == Priority.P0_CRITICAL:
            return "CRITICAL"
        elif highest.priority == Priority.P1_HIGH:
            return "WARNING"
        elif highest.priority == Priority.P2_MEDIUM or anomaly_score > 0.5:
            return "CAUTION"
        else:
            return "SAFE"

    def _compile_statistics(self, raw_threats: List[Dict],
                             filtered_threats: List[Dict],
                             priorities: List[ThreatPriority],
                             filter_results: List[FilterResult]) -> Dict[str, Any]:
        """Compile comprehensive statistics"""
        # Count by severity
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for threat in filtered_threats:
            severity = threat.get('severity', 'LOW')
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Count by priority
        by_priority = {p.value: 0 for p in Priority}
        for priority in priorities:
            by_priority[priority.priority.value] += 1
        
        # Filter statistics
        filter_stats = self.fp_filter.get_statistics()
        
        # Confidence statistics
        confidence_stats = self.confidence_scorer.get_accuracy_stats()
        
        # Prioritization statistics
        priority_stats = self.prioritizer.get_statistics()
        
        return {
            'raw_threats_detected': len(raw_threats),
            'false_positives_filtered': len(raw_threats) - len(filtered_threats),
            'genuine_threats': len(filtered_threats),
            'by_severity': by_severity,
            'by_priority': by_priority,
            'filter_statistics': filter_stats,
            'confidence_statistics': confidence_stats,
            'priority_statistics': priority_stats,
            'total_detections': self.detection_count,
            'total_threats_in_history': len(self.threat_history)
        }

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of all detected threats"""
        if not self.threat_history:
            return {
                'total_threats': 0,
                'by_type': {},
                'by_severity': {},
                'recent_threats': []
            }
        
        by_type = {}
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for threat in self.threat_history:
            threat_type = threat.get('type', 'UNKNOWN')
            severity = threat.get('severity', 'LOW')
            
            by_type[threat_type] = by_type.get(threat_type, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            'total_threats': len(self.threat_history),
            'by_type': by_type,
            'by_severity': by_severity,
            'recent_threats': self.threat_history[-10:]
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

    def provide_feedback(self, threat_id: str, was_true_positive: bool):
        """Provide feedback for adaptive learning"""
        self.confidence_scorer.update_accuracy(was_true_positive)
        
        if was_true_positive:
            self.logger.info(f"Feedback: {threat_id} was a true positive")
        else:
            self.logger.info(f"Feedback: {threat_id} was a false positive")
            self.false_positive_count += 1

    def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health metrics"""
        total_detections = self.detection_count
        fp_rate = (self.false_positive_count / max(total_detections, 1)) * 100
        
        return {
            'total_detections': total_detections,
            'false_positive_rate': round(fp_rate, 2),
            'true_positive_rate': round(100 - fp_rate, 2),
            'threats_in_history': len(self.threat_history),
            'baseline_ready': self.anomaly_detector.is_trained,
            'baseline_progress': min(len(self.anomaly_detector.cpu_history), 20) * 5,
            'components_status': {
                'rule_engine': 'ACTIVE',
                'anomaly_detector': 'ACTIVE' if self.anomaly_detector.is_trained else 'LEARNING',
                'false_positive_filter': 'ACTIVE',
                'threat_prioritizer': 'ACTIVE',
                'confidence_scorer': 'ACTIVE',
                'threat_intelligence': 'ACTIVE',
                'response_optimizer': 'ACTIVE'
            }
        }


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def create_detector(config: Dict[str, Any] = None) -> EnhancedThreatDetector:
    """Create and return an enhanced threat detector"""
    return EnhancedThreatDetector(config)


def analyze_snapshot(snapshot: Dict[str, Any],
                     auto_respond: bool = True,
                     config: Dict[str, Any] = None) -> DetectionResult:
    """Analyze a system snapshot and return results"""
    detector = create_detector(config)
    return detector.analyze(snapshot, auto_respond)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  SENTINEL - Enhanced Threat Detection System v2.0")
    print("  AI-Powered Security with Advanced False Positive Filtering")
    print("=" * 70)
    print()
    print("System Components:")
    print("  ✓ Rule-based Detection Engine (60+ threat types)")
    print("  ✓ ML Anomaly Detection")
    print("  ✓ False Positive Filtering Engine")
    print("  ✓ Intelligent Threat Prioritization")
    print("  ✓ Adaptive Confidence Scoring")
    print("  ✓ Threat Intelligence Integration")
    print("  ✓ Response Optimization")
    print()
    print("Key Features:")
    print("  • Multi-layer detection with minimal false positives")
    print("  • Context-aware threat validation")
    print("  • Behavioral baseline learning")
    print("  • Threat correlation and deduplication")
    print("  • Priority-based response automation")
    print("  • Comprehensive reporting and statistics")
    print()
    print("=" * 70)
    print("  Detection Engine Ready - Waiting for system snapshots...")
    print("=" * 70)
    
    # Initialize detector
    detector = EnhancedThreatDetector()
    
    # Print system health
    health = detector.get_system_health()
    print(f"\n📊 System Health:")
    print(f"  Components: {len(health['components_status'])} active")
    print(f"  Baseline: {'Ready' if health['baseline_ready'] else 'Learning'}")
    print(f"  Progress: {health['baseline_progress']}%")
