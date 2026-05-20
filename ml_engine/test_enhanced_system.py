"""
SENTINEL - Enhanced Threat Detection System Test Suite
======================================================
Comprehensive testing of the enhanced threat detection system
with false positive filtering and intelligent prioritization.

Tests:
1. False positive filtering accuracy
2. Threat prioritization correctness
3. Confidence scoring adaptiveness
4. Threat correlation effectiveness
5. Response optimization
6. End-to-end detection pipeline

Author: SENTINEL Development Team
Version: 2.0.0
"""

import sys
import os
import datetime
import json
from typing import Dict, List, Any

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from ml_engine.enhanced_detector import EnhancedThreatDetector, DetectionResult
from ml_engine.false_positive_filter import FalsePositiveFilter, ValidationResult
from ml_engine.threat_prioritizer import ThreatPrioritizer, Priority


class TestResult:
    """Test result container"""
    def __init__(self, test_name: str, passed: bool, message: str, details: Dict = None):
        self.test_name = test_name
        self.passed = passed
        self.message = message
        self.details = details or {}
        self.timestamp = datetime.datetime.utcnow().isoformat()

    def __str__(self):
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return f"{status}: {self.test_name} - {self.message}"


class EnhancedSystemTester:
    """Comprehensive test suite for enhanced threat detection system"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.detector = EnhancedThreatDetector()

    def run_all_tests(self) -> List[TestResult]:
        """Run all test suites"""
        print("\n" + "=" * 70)
        print("  🛡️  SENTINEL Enhanced System Test Suite")
        print("=" * 70)
        
        # Run test suites
        self.test_false_positive_filtering()
        self.test_threat_prioritization()
        self.test_confidence_scoring()
        self.test_threat_correlation()
        self.test_response_optimization()
        self.test_end_to_end_detection()
        
        # Print summary
        self.print_summary()
        
        return self.results

    def test_false_positive_filtering(self):
        """Test false positive filtering accuracy"""
        print("\n📋 Test Suite: False Positive Filtering")
        print("-" * 70)
        
        # Test 1: Whitelist filtering
        self._test_whitelist_filtering()
        
        # Test 2: Context validation
        self._test_context_validation()
        
        # Test 3: Behavioral analysis
        self._test_behavioral_analysis()

    def _test_whitelist_filtering(self):
        """Test whitelist-based filtering"""
        # Create snapshot with whitelisted processes
        snapshot = self._create_normal_snapshot()
        
        # Add a threat targeting a whitelisted process
        threats = [{
            "type": "CRYPTOMINER_DETECTED",
            "severity": "HIGH",
            "confidence": 85,
            "description": "Cryptominer detected in chrome.exe",
            "target_pids": [1003],  # chrome.exe PID
            "auto_action": "SUSPEND_PROCESS"
        }]
        
        # Run filtering
        fp_filter = FalsePositiveFilter()
        filtered, results = fp_filter.filter_threats(
            threats, snapshot['system'], snapshot['processes']
        )
        
        # Chrome should be whitelisted, so threat should be filtered
        passed = len(filtered) == 0
        self.results.append(TestResult(
            "Whitelist Filtering - Known Safe Process",
            passed,
            f"Filtered {len(threats)} threats to {len(filtered)} (expected 0)",
            {"original": len(threats), "filtered": len(filtered)}
        ))
        
        print(f"  {'✓' if passed else '✗'} Whitelist filtering for known safe processes")

    def _test_context_validation(self):
        """Test context-aware validation"""
        # Create snapshot with high disk activity from backup
        snapshot = self._create_backup_snapshot()
        
        # Add ransomware threat
        threats = [{
            "type": "RANSOMWARE_ACTIVITY",
            "severity": "CRITICAL",
            "confidence": 90,
            "description": "High disk activity with encryption processes",
            "target_pids": [],
            "auto_action": "EMERGENCY_SHUTDOWN"
        }]
        
        # Run filtering
        fp_filter = FalsePositiveFilter()
        filtered, results = fp_filter.filter_threats(
            threats, snapshot['system'], snapshot['processes']
        )
        
        # Should be filtered as false positive (backup activity)
        passed = len(filtered) == 0
        self.results.append(TestResult(
            "Context Validation - Backup Activity",
            passed,
            f"Correctly identified backup activity as false positive",
            {"original": len(threats), "filtered": len(filtered)}
        ))
        
        print(f"  {'✓' if passed else '✗'} Context validation for backup activity")

    def _test_behavioral_analysis(self):
        """Test behavioral baseline analysis"""
        # Create snapshot with normal behavior
        snapshot = self._create_normal_snapshot()
        
        # Add anomaly threat
        threats = [{
            "type": "ANOMALY",
            "severity": "MEDIUM",
            "confidence": 60,
            "description": "System behavior anomaly detected",
            "auto_action": "ALERT_ONLY"
        }]
        
        # Run filtering
        fp_filter = FalsePositiveFilter()
        
        # Update baseline multiple times
        for _ in range(25):
            fp_filter.behavioral_analyzer.update_baseline(snapshot['system'])
        
        filtered, results = fp_filter.filter_threats(
            threats, snapshot['system'], snapshot['processes']
        )
        
        # Low confidence anomaly should be filtered
        passed = len(filtered) == 0
        self.results.append(TestResult(
            "Behavioral Analysis - Low Confidence Anomaly",
            passed,
            f"Filtered low-confidence non-anomalous threat",
            {"original": len(threats), "filtered": len(filtered)}
        ))
        
        print(f"  {'✓' if passed else '✗'} Behavioral analysis for low-confidence anomalies")

    def test_threat_prioritization(self):
        """Test threat prioritization correctness"""
        print("\n📋 Test Suite: Threat Prioritization")
        print("-" * 70)
        
        # Test 1: Priority ordering
        self._test_priority_ordering()
        
        # Test 2: Critical threat detection
        self._test_critical_threat_detection()

    def _test_priority_ordering(self):
        """Test that threats are prioritized correctly"""
        snapshot = self._create_normal_snapshot()
        
        # Create threats with different severities
        threats = [
            {
                "type": "ADWARE_DETECTED",
                "severity": "LOW",
                "confidence": 70,
                "description": "Adware detected",
                "auto_action": "ALERT_ONLY"
            },
            {
                "type": "RANSOMWARE_DETECTED",
                "severity": "CRITICAL",
                "confidence": 95,
                "description": "Ransomware detected",
                "auto_action": "EMERGENCY_SHUTDOWN"
            },
            {
                "type": "CRYPTOMINER_DETECTED",
                "severity": "MEDIUM",
                "confidence": 80,
                "description": "Cryptominer detected",
                "auto_action": "SUSPEND_PROCESS"
            }
        ]
        
        # Prioritize
        prioritizer = ThreatPrioritizer()
        priorities = prioritizer.prioritize_threats(threats, snapshot)
        
        # Check ordering (highest priority first)
        passed = (
            len(priorities) == 3 and
            priorities[0].threat_type == "RANSOMWARE_DETECTED" and
            priorities[0].priority == Priority.P0_CRITICAL and
            priorities[2].threat_type == "ADWARE_DETECTED"
        )
        
        self.results.append(TestResult(
            "Priority Ordering",
            passed,
            f"Correctly prioritized {len(priorities)} threats",
            {
                "order": [p.threat_type for p in priorities],
                "priorities": [p.priority.value for p in priorities]
            }
        ))
        
        print(f"  {'✓' if passed else '✗'} Threat priority ordering")

    def _test_critical_threat_detection(self):
        """Test critical threat detection and escalation"""
        snapshot = self._create_normal_snapshot()
        
        # Create critical threat
        threats = [{
            "type": "ZERO_DAY_EXPLOIT_INDICATOR",
            "severity": "CRITICAL",
            "confidence": 90,
            "description": "Zero-day exploit detected",
            "auto_action": "ISOLATE_AND_ALERT"
        }]
        
        # Prioritize
        prioritizer = ThreatPrioritizer()
        priorities = prioritizer.prioritize_threats(threats, snapshot)
        
        # Check critical detection
        passed = (
            len(priorities) == 1 and
            priorities[0].priority == Priority.P0_CRITICAL and
            priorities[0].escalation_required == True
        )
        
        self.results.append(TestResult(
            "Critical Threat Detection",
            passed,
            f"Correctly identified critical threat requiring escalation",
            {"priority": priorities[0].priority.value if priorities else "NONE"}
        ))
        
        print(f"  {'✓' if passed else '✗'} Critical threat detection and escalation")

    def test_confidence_scoring(self):
        """Test adaptive confidence scoring"""
        print("\n📋 Test Suite: Confidence Scoring")
        print("-" * 70)
        
        # Test confidence adjustment
        self._test_confidence_adjustment()

    def _test_confidence_adjustment(self):
        """Test confidence score adjustment"""
        snapshot = self._create_normal_snapshot()
        
        # Create threat with base confidence
        threat = {
            "type": "TROJAN_DETECTED",
            "severity": "HIGH",
            "confidence": 75,
            "description": "Trojan detected",
            "signature_matched": True,
            "anomaly_score": 0.8,
            "auto_action": "SUSPEND_PROCESS"
        }
        
        # Calculate adaptive confidence
        scorer = self.detector.confidence_scorer
        adjusted = scorer.calculate_confidence(threat, snapshot)
        
        # Should be boosted due to signature match and anomaly
        passed = adjusted > threat['confidence']
        
        self.results.append(TestResult(
            "Confidence Adjustment",
            passed,
            f"Adjusted confidence from {threat['confidence']} to {adjusted}",
            {"original": threat['confidence'], "adjusted": adjusted}
        ))
        
        print(f"  {'✓' if passed else '✗'} Adaptive confidence scoring")

    def test_threat_correlation(self):
        """Test threat correlation effectiveness"""
        print("\n📋 Test Suite: Threat Correlation")
        print("-" * 70)
        
        # Test duplicate removal
        self._test_duplicate_removal()

    def _test_duplicate_removal(self):
        """Test duplicate threat removal"""
        # Create duplicate threats
        threats = [
            {
                "type": "TROJAN_DETECTED",
                "severity": "HIGH",
                "confidence": 85,
                "description": "Trojan detected",
                "target_pids": [1234],
                "auto_action": "SUSPEND_PROCESS"
            },
            {
                "type": "TROJAN_DETECTED",
                "severity": "HIGH",
                "confidence": 85,
                "description": "Trojan detected (duplicate)",
                "target_pids": [1234],
                "auto_action": "SUSPEND_PROCESS"
            }
        ]
        
        # Run correlation
        fp_filter = FalsePositiveFilter()
        correlated = fp_filter.threat_correlator.correlate_threats(threats)
        
        # Should remove duplicate
        passed = len(correlated) == 1
        
        self.results.append(TestResult(
            "Duplicate Removal",
            passed,
            f"Removed {len(threats) - len(correlated)} duplicate threats",
            {"original": len(threats), "correlated": len(correlated)}
        ))
        
        print(f"  {'✓' if passed else '✗'} Duplicate threat removal")

    def test_response_optimization(self):
        """Test response optimization"""
        print("\n📋 Test Suite: Response Optimization")
        print("-" * 70)
        
        # Test response proportionality
        self._test_response_proportionality()

    def _test_response_proportionality(self):
        """Test that responses are proportionate to threat severity"""
        snapshot = self._create_normal_snapshot()
        
        # Create low severity threat
        threat = {
            "type": "ADWARE_DETECTED",
            "severity": "LOW",
            "confidence": 70,
            "description": "Adware detected",
            "auto_action": "ALERT_ONLY"
        }
        
        # Create priority
        prioritizer = ThreatPrioritizer()
        priorities = prioritizer.prioritize_threats([threat], snapshot)
        
        if priorities:
            # Optimize response
            optimizer = self.detector.response_optimizer
            actions = optimizer.optimize_response(threat, priorities[0], snapshot)
            
            # Should not have aggressive actions for low severity
            aggressive_actions = ['EMERGENCY_SHUTDOWN', 'ISOLATE_AND_ALERT', 'LOCKDOWN']
            has_aggressive = any(a in actions for a in aggressive_actions)
            
            passed = not has_aggressive
            
            self.results.append(TestResult(
                "Response Proportionality",
                passed,
                f"Low severity threat has proportionate response",
                {"actions": actions}
            ))
            
            print(f"  {'✓' if passed else '✗'} Response proportionality for low severity threats")

    def test_end_to_end_detection(self):
        """Test end-to-end detection pipeline"""
        print("\n📋 Test Suite: End-to-End Detection")
        print("-" * 70)
        
        # Test complete detection pipeline
        self._test_complete_pipeline()

    def _test_complete_pipeline(self):
        """Test complete detection pipeline"""
        # Create snapshot with genuine threat
        snapshot = self._create_threat_snapshot()
        
        # Run full analysis
        result = self.detector.analyze(snapshot, auto_respond=False)
        
        # Should detect threats
        passed = (
            len(result.threats) > 0 and
            result.system_status in ['WARNING', 'CRITICAL'] and
            len(result.priorities) > 0
        )
        
        self.results.append(TestResult(
            "End-to-End Detection",
            passed,
            f"Detected {len(result.threats)} threats with status {result.system_status}",
            {
                "threats": len(result.threats),
                "status": result.system_status,
                "priorities": len(result.priorities),
                "processing_time_ms": result.processing_time_ms
            }
        ))
        
        print(f"  {'✓' if passed else '✗'} End-to-end detection pipeline")

    def _create_normal_snapshot(self) -> Dict[str, Any]:
        """Create a normal system snapshot"""
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
                    "name": "chrome.exe",
                    "cpu_percent": 15.0,
                    "memory_percent": 45.0,
                    "status": "running",
                    "exe_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "username": "user",
                    "risk_score": 5,
                    "is_known": True,
                    "command_line": "chrome.exe --type=renderer"
                },
                {
                    "pid": 1002,
                    "name": "explorer.exe",
                    "cpu_percent": 2.0,
                    "memory_percent": 8.0,
                    "status": "running",
                    "exe_path": "C:\\Windows\\explorer.exe",
                    "username": "user",
                    "risk_score": 0,
                    "is_known": True,
                    "command_line": "explorer.exe"
                }
            ],
            "network": {
                "connections": [
                    {
                        "local_ip": "192.168.1.100",
                        "local_port": 50000,
                        "remote_ip": "104.21.5.1",
                        "remote_port": 443,
                        "status": "ESTABLISHED",
                        "pid": 1001,
                        "is_suspicious": False,
                        "reason": []
                    }
                ],
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

    def _create_backup_snapshot(self) -> Dict[str, Any]:
        """Create a snapshot simulating backup activity"""
        snapshot = self._create_normal_snapshot()
        
        # Add backup process
        snapshot['processes'].append({
            "pid": 1003,
            "name": "backup.exe",
            "cpu_percent": 85.0,
            "memory_percent": 30.0,
            "status": "running",
            "exe_path": "C:\\Program Files\\Backup\\backup.exe",
            "username": "user",
            "risk_score": 0,
            "is_known": True,
            "command_line": "backup.exe --full"
        })
        
        # High disk activity
        snapshot['system']['disk_percent'] = 95.0
        
        return snapshot

    def _create_threat_snapshot(self) -> Dict[str, Any]:
        """Create a snapshot with genuine threats"""
        snapshot = self._create_normal_snapshot()
        
        # Add malicious process
        snapshot['processes'].append({
            "pid": 9999,
            "name": "suspicious.exe",
            "cpu_percent": 90.0,
            "memory_percent": 40.0,
            "status": "running",
            "exe_path": "C:\\Users\\user\\AppData\\Local\\Temp\\suspicious.exe",
            "username": "user",
            "risk_score": 85,
            "is_known": False,
            "command_line": "suspicious.exe -hidden"
        })
        
        # Add suspicious network connection
        snapshot['network']['connections'].append({
            "local_ip": "192.168.1.100",
            "local_port": 50001,
            "remote_ip": "45.33.32.156",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "pid": 9999,
            "is_suspicious": True,
            "reason": ["suspicious_port"]
        })
        
        return snapshot

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 70)
        print("  📊 Test Summary")
        print("=" * 70)
        
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        
        print(f"\n  Total Tests: {len(self.results)}")
        print(f"  ✓ Passed: {passed}")
        print(f"  ✗ Failed: {failed}")
        print(f"  Success Rate: {(passed/len(self.results)*100):.1f}%")
        
        if failed > 0:
            print("\n  Failed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"    - {result.test_name}: {result.message}")
        
        print("\n" + "=" * 70)
        
        # Save results to file
        self._save_results()

    def _save_results(self):
        """Save test results to file"""
        try:
            results_file = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'test_results.json'
            )
            
            results_data = {
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'total_tests': len(self.results),
                'passed': sum(1 for r in self.results if r.passed),
                'failed': sum(1 for r in self.results if not r.passed),
                'results': [
                    {
                        'test_name': r.test_name,
                        'passed': r.passed,
                        'message': r.message,
                        'details': r.details,
                        'timestamp': r.timestamp
                    }
                    for r in self.results
                ]
            }
            
            with open(results_file, 'w') as f:
                json.dump(results_data, f, indent=2)
            
            print(f"\n  Results saved to: {results_file}")
        except Exception as e:
            print(f"\n  Warning: Could not save results: {e}")


def main():
    """Main test entry point"""
    tester = EnhancedSystemTester()
    results = tester.run_all_tests()
    
    # Exit with appropriate code
    failed = sum(1 for r in results if not r.passed)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
