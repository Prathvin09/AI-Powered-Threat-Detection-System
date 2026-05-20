"""
SENTINEL - Comprehensive Threat Detection Engine v2.0
=====================================================
AI-Powered Endpoint Security System for Final Year Project

Detects 60+ threat types across 12 categories:
- Malware (Ransomware, Trojan, Spyware, Rootkit, Cryptominer, Virus/Worm, Adware)
- Social Engineering (Phishing, Baiting, Infostealer, Tech Support Scam)
- Network Attacks (DDoS, MITM, DNS Spoofing, SSRF)
- Code Injection (SQL Injection, XSS, Command Injection, LDAP Injection, XXE)
- Fileless & Advanced Attacks (Fileless Malware, Process Injection, DLL Side-Loading)
- Web-Based Threats (Cryptojacking, Drive-by Download, CSRF, Typosquatting)
- Data Theft (Packet Sniffing, Data Exfiltration, Session Hijacking)
- Unauthorized Access (Brute Force, Backdoor, Credential Stuffing, Path Traversal)
- Harm & Disruption (Resource Exhaustion, Botnet, Logic Bomb)
- Infrastructure (IoT Attack, Supply Chain, Insider Threat, Firmware Integrity)
- Zero-Day & Advanced (Zero-Day Exploit, ML Anomaly Detection)

Author: SENTINEL Development Team
Version: 2.0.0
License: Educational/Final Year Project
"""

import json
import datetime
import random
import re
import hashlib
import logging
import os
import subprocess
import shutil
import ctypes
from collections import deque
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path

# Third-party imports
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available - some auto-response features will be limited")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('SENTINEL')


class Severity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AutoAction(Enum):
    """Automated response actions"""
    ALERT_ONLY = "ALERT_ONLY"
    SUSPEND_PROCESS = "SUSPEND_PROCESS"
    BLOCK_IP = "BLOCK_IP"
    ISOLATE_AND_ALERT = "ISOLATE_AND_ALERT"
    LOCKDOWN = "LOCKDOWN"
    EMERGENCY_SHUTDOWN = "EMERGENCY_SHUTDOWN"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    RESET_SESSION = "RESET_SESSION"
    CLEAR_CACHE = "CLEAR_CACHE"
    DISABLE_SERVICE = "DISABLE_SERVICE"


@dataclass
class ThreatAlert:
    """Standardized threat alert structure"""
    type: str
    severity: str
    confidence: int
    description: str
    preventive_steps: List[str]
    auto_action: str
    detected_at: str
    status: str
    id: str
    icon: str
    color: str
    user_message: str
    immediate_action: str
    processes: Optional[List[str]] = None
    exe_path: Optional[str] = None
    pid: Optional[int] = None
    target_pids: Optional[List[int]] = None
    target_ips: Optional[List[str]] = None
    anomaly_score: Optional[float] = None
    raw_data: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ============================================================================
# AUTO-RESPONSE ENGINE - Actual Execution of Security Responses
# ============================================================================

class AutoResponseResult:
    """Result of an auto-response execution"""
    def __init__(self, success: bool, action: str, message: str, 
                 rollback_instructions: List[str] = None, error: str = None):
        self.success = success
        self.action = action
        self.message = message
        self.rollback_instructions = rollback_instructions or []
        self.error = error
        self.timestamp = datetime.datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "action": self.action,
            "message": self.message,
            "rollback_instructions": self.rollback_instructions,
            "error": self.error,
            "timestamp": self.timestamp
        }


class AutoResponseEngine:
    """
    Production-ready auto-response engine that actually executes security responses.
    Uses psutil, subprocess, and Windows APIs for real system modifications.
    All actions are logged and include rollback capabilities.
    """
    
    def __init__(self, quarantine_dir: str = None, log_dir: str = None):
        self.logger = logging.getLogger('SENTINEL.AutoResponseEngine')
        self.quarantine_dir = quarantine_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'quarantine'
        )
        self.log_dir = log_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'logs'
        )
        self.action_log: List[Dict] = []
        self.blocked_ips: set = set()
        self.suspended_pids: set = set()
        self.disabled_services: set = set()
        self.quarantined_files: List[Dict] = []
        
        # Ensure directories exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.logger.info(f"AutoResponseEngine initialized. Quarantine: {self.quarantine_dir}")
    
    def execute(self, action: AutoAction, threat_data: Dict) -> AutoResponseResult:
        """
        Execute an auto-response action based on threat data.
        
        Args:
            action: The AutoAction to execute
            threat_data: Dictionary containing threat details (pids, ips, filepath, etc.)
            
        Returns:
            AutoResponseResult with execution status and rollback instructions
        """
        self.logger.info(f"Executing auto-response: {action.value} for threat: {threat_data.get('type', 'Unknown')}")
        
        try:
            if action == AutoAction.ALERT_ONLY:
                result = self._execute_alert_only(threat_data)
            elif action == AutoAction.SUSPEND_PROCESS:
                result = self.execute_suspend_process(threat_data)
            elif action == AutoAction.BLOCK_IP:
                result = self.execute_block_ip(threat_data)
            elif action == AutoAction.ISOLATE_AND_ALERT:
                result = self.execute_isolate_system(threat_data)
            elif action == AutoAction.LOCKDOWN:
                result = self.execute_lockdown(threat_data)
            elif action == AutoAction.EMERGENCY_SHUTDOWN:
                result = self.execute_emergency_shutdown(threat_data)
            elif action == AutoAction.QUARANTINE_FILE:
                result = self.execute_quarantine_file(threat_data)
            elif action == AutoAction.RESET_SESSION:
                result = self.execute_reset_session(threat_data)
            elif action == AutoAction.CLEAR_CACHE:
                result = self.execute_clear_cache(threat_data)
            elif action == AutoAction.DISABLE_SERVICE:
                result = self.execute_disable_service(threat_data)
            else:
                result = AutoResponseResult(
                    success=False,
                    action=action.value,
                    message=f"Unknown action: {action.value}",
                    error=f"Action {action.value} not implemented"
                )
            
            # Log the action
            self.action_log.append({
                "timestamp": result.timestamp,
                "action": action.value,
                "threat_type": threat_data.get('type', 'Unknown'),
                "success": result.success,
                "message": result.message
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing auto-response {action.value}: {e}")
            return AutoResponseResult(
                success=False,
                action=action.value,
                message=f"Failed to execute {action.value}",
                error=str(e)
            )
    
    def _execute_alert_only(self, threat_data: Dict) -> AutoResponseResult:
        """Log and notify only - no system changes"""
        message = f"ALERT: {threat_data.get('type', 'Unknown threat')} - {threat_data.get('description', 'No description')}"
        self.logger.warning(message)
        
        return AutoResponseResult(
            success=True,
            action=AutoAction.ALERT_ONLY.value,
            message=message,
            rollback_instructions=["No action taken - alert only"]
        )
    
    def execute_suspend_process(self, threat_data: Dict) -> AutoResponseResult:
        """
        Actually terminate/suspend malicious processes using psutil.
        
        Args:
            threat_data: Contains 'target_pids' or 'pid' list
            
        Returns:
            AutoResponseResult with termination status
        """
        if not PSUTIL_AVAILABLE:
            return AutoResponseResult(
                success=False,
                action=AutoAction.SUSPEND_PROCESS.value,
                message="psutil not available - cannot terminate processes",
                error="psutil module not installed",
                rollback_instructions=["Install psutil: pip install psutil"]
            )
        
        pids = threat_data.get('target_pids', [])
        if not pids and threat_data.get('pid'):
            pids = [threat_data['pid']]
        
        if not pids:
            return AutoResponseResult(
                success=False,
                action=AutoAction.SUSPEND_PROCESS.value,
                message="No process IDs specified for termination",
                error="No PIDs provided"
            )
        
        terminated = []
        failed = []
        rollback_instructions = []
        
        for pid in pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc_exe = proc.exe()
                
                # First try graceful termination
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                    terminated.append((pid, proc_name))
                    self.suspended_pids.add(pid)
                    self.logger.info(f"Terminated process {pid} ({proc_name})")
                except psutil.TimeoutExpired:
                    # Force kill if terminate doesn't work
                    proc.kill()
                    terminated.append((pid, proc_name))
                    self.suspended_pids.add(pid)
                    self.logger.info(f"Force-killed process {pid} ({proc_name})")
                
                rollback_instructions.append(
                    f"Process {proc_name} (PID: {pid}) was terminated. "
                    f"If this was legitimate, restart the application from: {proc_exe}"
                )
                
            except psutil.NoSuchProcess:
                failed.append((pid, "Process already exited"))
                self.logger.warning(f"Process {pid} already exited")
            except psutil.AccessDenied:
                failed.append((pid, "Access denied - run as administrator"))
                self.logger.error(f"Access denied for process {pid}")
            except Exception as e:
                failed.append((pid, str(e)))
                self.logger.error(f"Error terminating process {pid}: {e}")
        
        if terminated:
            term_list = ", ".join([f"{name} (PID: {p})" for p, name in terminated])
            return AutoResponseResult(
                success=True,
                action=AutoAction.SUSPEND_PROCESS.value,
                message=f"Successfully terminated: {term_list}",
                rollback_instructions=rollback_instructions
            )
        elif failed:
            fail_list = ", ".join([f"PID {p}: {r}" for p, r in failed])
            return AutoResponseResult(
                success=False,
                action=AutoAction.SUSPEND_PROCESS.value,
                message=f"Failed to terminate processes: {fail_list}",
                error="All termination attempts failed",
                rollback_instructions=["Run SENTINEL as Administrator for full process control"]
            )
        else:
            return AutoResponseResult(
                success=True,
                action=AutoAction.SUSPEND_PROCESS.value,
                message="No processes required termination",
                rollback_instructions=[]
            )
    
    def execute_block_ip(self, threat_data: Dict) -> AutoResponseResult:
        """
        Block IP addresses using Windows Firewall (netsh commands).
        
        Args:
            threat_data: Contains 'target_ips' list
            
        Returns:
            AutoResponseResult with blocking status
        """
        ips = threat_data.get('target_ips', [])
        if not ips:
            return AutoResponseResult(
                success=False,
                action=AutoAction.BLOCK_IP.value,
                message="No IP addresses specified for blocking",
                error="No IPs provided"
            )
        
        # Never block localhost/loopback IPs - these are the app's own connections
        SAFE_IPS = {'127.0.0.1', 'localhost', '0.0.0.0', '::1'}
        ips = [ip for ip in ips if ip not in SAFE_IPS]
        if not ips:
            self.logger.info("All target IPs are localhost/loopback - skipping block")
            return AutoResponseResult(
                success=True,
                action=AutoAction.BLOCK_IP.value,
                message="Skipped blocking localhost/loopback IPs (safe self-connections)",
                rollback_instructions=[]
            )
        
        blocked = []
        failed = []
        rollback_instructions = []
        
        for ip in ips:
            try:
                # Create a unique rule name
                rule_name = f"SENTINEL_BLOCK_{ip.replace('.', '_').replace(':', '_')}"
                
                # Check if rule already exists
                check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
                check_result = subprocess.run(
                    check_cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                
                if "No rules match" not in check_result.stdout:
                    self.logger.info(f"Firewall rule for {ip} already exists")
                    blocked.append(ip)
                    self.blocked_ips.add(ip)
                    continue
                
                # Block outbound connections to this IP
                block_cmd = (
                    f'netsh advfirewall firewall add rule '
                    f'name="{rule_name}" '
                    f'dir=out '
                    f'action=block '
                    f'remoteip={ip} '
                    f'enable=yes '
                    f'profile=any '
                    f'description="Blocked by SENTINEL - {threat_data.get("type", "Threat")}"'
                )
                
                result = subprocess.run(
                    block_cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0 or "Ok." in result.stdout:
                    blocked.append(ip)
                    self.blocked_ips.add(ip)
                    self.logger.info(f"Blocked IP {ip} in Windows Firewall")
                    rollback_instructions.append(
                        f'To unblock {ip}, run: netsh advfirewall firewall delete rule name="{rule_name}"'
                    )
                else:
                    failed.append((ip, result.stderr or "Unknown error"))
                    self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                failed.append((ip, "Command timeout"))
                self.logger.error(f"Timeout blocking IP {ip}")
            except Exception as e:
                failed.append((ip, str(e)))
                self.logger.error(f"Error blocking IP {ip}: {e}")
        
        if blocked:
            return AutoResponseResult(
                success=True,
                action=AutoAction.BLOCK_IP.value,
                message=f"Blocked {len(blocked)} IP(s): {', '.join(blocked)}",
                rollback_instructions=rollback_instructions
            )
        elif failed:
            return AutoResponseResult(
                success=False,
                action=AutoAction.BLOCK_IP.value,
                message=f"Failed to block IPs: {failed}",
                error="Firewall modification failed - run as Administrator",
                rollback_instructions=[
                    "Run SENTINEL as Administrator",
                    "Manually add firewall rules via Windows Defender Firewall"
                ]
            )
        else:
            return AutoResponseResult(
                success=True,
                action=AutoAction.BLOCK_IP.value,
                message="IPs already blocked or no action needed",
                rollback_instructions=[]
            )
    
    def execute_isolate_system(self, threat_data: Dict) -> AutoResponseResult:
        """
        Isolate system by disabling network adapters.
        WARNING: This will disconnect all network connectivity.
        
        Args:
            threat_data: Threat information
            
        Returns:
            AutoResponseResult with isolation status
        """
        rollback_instructions = []
        disabled_adapters = []
        
        try:
            # Get all network adapters using netsh
            get_adapters_cmd = 'netsh interface show interface'
            result = subprocess.run(
                get_adapters_cmd, shell=True, capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.ISOLATE_AND_ALERT.value,
                    message="Failed to enumerate network adapters",
                    error=result.stderr,
                    rollback_instructions=["Run as Administrator to disable network adapters"]
                )
            
            # Parse adapter names (skip header lines)
            lines = result.stdout.strip().split('\n')[3:]  # Skip header
            adapters = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    # Adapter name is the last column(s)
                    adapter_name = ' '.join(parts[3:])
                    adapters.append(adapter_name)
            
            # Disable each adapter
            for adapter in adapters:
                try:
                    disable_cmd = f'netsh interface set interface "{adapter}" disable'
                    disable_result = subprocess.run(
                        disable_cmd, shell=True, capture_output=True, text=True, timeout=10
                    )
                    
                    if disable_result.returncode == 0:
                        disabled_adapters.append(adapter)
                        self.logger.info(f"Disabled network adapter: {adapter}")
                        rollback_instructions.append(
                            f'To re-enable network, run: netsh interface set interface "{adapter}" enable'
                        )
                    else:
                        self.logger.warning(f"Failed to disable adapter {adapter}: {disable_result.stderr}")
                        
                except Exception as e:
                    self.logger.error(f"Error disabling adapter {adapter}: {e}")
            
            if disabled_adapters:
                return AutoResponseResult(
                    success=True,
                    action=AutoAction.ISOLATE_AND_ALERT.value,
                    message=f"Network isolation complete. Disabled {len(disabled_adapters)} adapter(s): {', '.join(disabled_adapters)}",
                    rollback_instructions=rollback_instructions + [
                        "Re-enable network adapters after threat is neutralized",
                        "Run network diagnostics to verify connectivity"
                    ]
                )
            else:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.ISOLATE_AND_ALERT.value,
                    message="No network adapters could be disabled",
                    error="Requires Administrator privileges",
                    rollback_instructions=["Run SENTINEL as Administrator"]
                )
                
        except subprocess.TimeoutExpired:
            return AutoResponseResult(
                success=False,
                action=AutoAction.ISOLATE_AND_ALERT.value,
                message="Command timeout while isolating network",
                error="Timeout",
                rollback_instructions=["Manually disable network adapter in Network Connections"]
            )
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.ISOLATE_AND_ALERT.value,
                message=f"Network isolation failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Manually disable network via Control Panel > Network Connections"]
            )
    
    def execute_lockdown(self, threat_data: Dict) -> AutoResponseResult:
        """
        Implement system lockdown:
        - Disable guest account
        - Enable enhanced security features
        - Lock workstation
        
        Args:
            threat_data: Threat information
            
        Returns:
            AutoResponseResult with lockdown status
        """
        rollback_instructions = []
        actions_taken = []
        
        try:
            # 1. Disable Guest account
            try:
                guest_disable = subprocess.run(
                    'net user guest /active:no',
                    shell=True, capture_output=True, text=True, timeout=10
                )
                if guest_disable.returncode == 0:
                    actions_taken.append("Guest account disabled")
                    rollback_instructions.append("To re-enable guest: net user guest /active:yes")
                self.logger.info("Guest account disabled")
            except Exception as e:
                self.logger.warning(f"Could not disable guest account: {e}")
            
            # 2. Lock the workstation immediately
            try:
                # Use Windows API to lock workstation
                ctypes.windll.user32.LockWorkStation()
                actions_taken.append("Workstation locked")
                rollback_instructions.append("Unlock workstation with your credentials")
                self.logger.info("Workstation locked")
            except Exception as e:
                self.logger.warning(f"Could not lock workstation: {e}")
            
            # 3. Enable Windows Defender real-time protection (if disabled)
            try:
                defender_enable = subprocess.run(
                    'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"',
                    shell=True, capture_output=True, text=True, timeout=15
                )
                if defender_enable.returncode == 0:
                    actions_taken.append("Windows Defender real-time protection enabled")
                    rollback_instructions.append("Defender settings can be adjusted in Windows Security")
                self.logger.info("Windows Defender real-time protection enabled")
            except Exception as e:
                self.logger.warning(f"Could not enable Defender: {e}")
            
            # 4. Clear clipboard (potential credential theft prevention)
            try:
                subprocess.run(
                    'powershell -Command "Clear-Clipboard"',
                    shell=True, capture_output=True, text=True, timeout=5
                )
                actions_taken.append("Clipboard cleared")
                self.logger.info("Clipboard cleared")
            except Exception as e:
                self.logger.warning(f"Could not clear clipboard: {e}")
            
            if actions_taken:
                return AutoResponseResult(
                    success=True,
                    action=AutoAction.LOCKDOWN.value,
                    message=f"Lockdown complete: {'; '.join(actions_taken)}",
                    rollback_instructions=rollback_instructions
                )
            else:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.LOCKDOWN.value,
                    message="Lockdown actions failed - requires Administrator",
                    error="Insufficient privileges",
                    rollback_instructions=["Run SENTINEL as Administrator"]
                )
                
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.LOCKDOWN.value,
                message=f"Lockdown failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Manually secure system settings"]
            )
    
    def execute_emergency_shutdown(self, threat_data: Dict) -> AutoResponseResult:
        """
        Initiate safe system shutdown to prevent damage.
        Used for critical threats like active ransomware encryption.
        
        Args:
            threat_data: Threat information
            
        Returns:
            AutoResponseResult (note: system will shutdown if successful)
        """
        try:
            self.logger.critical("EMERGENCY SHUTDOWN INITIATED - Critical threat detected")
            
            # Log the shutdown reason
            shutdown_log = os.path.join(self.log_dir, f"emergency_shutdown_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            with open(shutdown_log, 'w') as f:
                f.write(f"Emergency Shutdown Log\n")
                f.write(f"Timestamp: {datetime.datetime.utcnow().isoformat()}\n")
                f.write(f"Threat Type: {threat_data.get('type', 'Unknown')}\n")
                f.write(f"Threat Description: {threat_data.get('description', 'N/A')}\n")
                f.write(f"Severity: {threat_data.get('severity', 'CRITICAL')}\n")
                f.write(f"\nAction: System shutdown initiated by SENTINEL Auto-Response Engine\n")
            
            # Initiate shutdown with 10 second warning
            # /s = shutdown, /t 10 = 10 second timeout, /c = comment
            shutdown_cmd = (
                f'shutdown /s /t 10 /c "SENTINEL Emergency Shutdown - Critical threat detected. '
                f'See logs at {shutdown_log}"'
            )
            
            result = subprocess.run(
                shutdown_cmd, shell=True, capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0:
                return AutoResponseResult(
                    success=True,
                    action=AutoAction.EMERGENCY_SHUTDOWN.value,
                    message="Emergency shutdown initiated. System will shut down in 10 seconds.",
                    rollback_instructions=[
                        "To abort shutdown, run: shutdown /a",
                        f"Review shutdown log at: {shutdown_log}",
                        "Boot from recovery media to scan for malware before normal boot",
                        "Do NOT reconnect to network until system is verified clean"
                    ]
                )
            else:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.EMERGENCY_SHUTDOWN.value,
                    message="Shutdown command failed",
                    error=result.stderr,
                    rollback_instructions=["Manually shut down system immediately", "Disconnect from network"]
                )
                
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.EMERGENCY_SHUTDOWN.value,
                message=f"Emergency shutdown failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Manually shut down system IMMEDIATELY", "Disconnect from network and power"]
            )
    
    def execute_quarantine_file(self, threat_data: Dict) -> AutoResponseResult:
        """
        Move suspicious files to quarantine directory.
        
        Args:
            threat_data: Contains 'exe_path' or file path to quarantine
            
        Returns:
            AutoResponseResult with quarantine status
        """
        filepath = threat_data.get('exe_path') or threat_data.get('filepath')
        
        if not filepath:
            return AutoResponseResult(
                success=False,
                action=AutoAction.QUARANTINE_FILE.value,
                message="No file path specified for quarantine",
                error="No filepath provided"
            )
        
        try:
            if not os.path.exists(filepath):
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.QUARANTINE_FILE.value,
                    message=f"File not found: {filepath}",
                    error="File does not exist"
                )
            
            # Create quarantine subdirectory with timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            threat_type = threat_data.get('type', 'Unknown').replace(' ', '_')
            quarantine_subdir = os.path.join(self.quarantine_dir, f"{threat_type}_{timestamp}")
            os.makedirs(quarantine_subdir, exist_ok=True)
            
            # Get file info before moving
            file_size = os.path.getsize(filepath)
            file_hash = self._calculate_file_hash(filepath)
            
            # Move file to quarantine
            filename = os.path.basename(filepath)
            quarantine_path = os.path.join(quarantine_subdir, filename)
            
            shutil.move(filepath, quarantine_path)
            
            # Create metadata file
            metadata = {
                "original_path": filepath,
                "quarantine_path": quarantine_path,
                "threat_type": threat_type,
                "timestamp": timestamp,
                "file_size": file_size,
                "file_hash": file_hash,
                "description": threat_data.get('description', 'N/A')
            }
            
            metadata_path = os.path.join(quarantine_subdir, f"{filename}.metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.quarantined_files.append(metadata)
            self.logger.info(f"Quarantined file: {filepath} -> {quarantine_path}")
            
            return AutoResponseResult(
                success=True,
                action=AutoAction.QUARANTINE_FILE.value,
                message=f"File quarantined: {filename}",
                rollback_instructions=[
                    f"File moved to: {quarantine_path}",
                    "DO NOT restore this file unless you are certain it is safe",
                    f"To restore (NOT RECOMMENDED): Move file back to {filepath}",
                    "Scan restored file with antivirus before opening"
                ]
            )
            
        except PermissionError:
            return AutoResponseResult(
                success=False,
                action=AutoAction.QUARANTINE_FILE.value,
                message=f"Permission denied: {filepath}",
                error="File is in use or requires Administrator",
                rollback_instructions=["Close the application using this file", "Run SENTINEL as Administrator"]
            )
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.QUARANTINE_FILE.value,
                message=f"Quarantine failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Manually move suspicious file to quarantine folder"]
            )
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {filepath}: {e}")
            return "error_calculating_hash"
    
    def execute_reset_session(self, threat_data: Dict) -> AutoResponseResult:
        """
        Reset browser sessions by clearing cookies and session data.
        
        Args:
            threat_data: Threat information
            
        Returns:
            AutoResponseResult with session reset status
        """
        actions_taken = []
        rollback_instructions = []
        
        try:
            # Clear browser cookies and cache using PowerShell
            browsers = {
                'Chrome': 'Google\\Chrome\\User Data\\Default',
                'Edge': 'Microsoft\\Edge\\User Data\\Default',
                'Firefox': 'Mozilla\\Firefox\\Profiles'
            }
            
            appdata = os.environ.get('APPDATA', '')
            localappdata = os.environ.get('LOCALAPPDATA', '')
            
            for browser, path_suffix in browsers.items():
                try:
                    if 'Firefox' in browser:
                        browser_path = os.path.join(appdata, path_suffix)
                    else:
                        browser_path = os.path.join(localappdata, path_suffix)
                    
                    # Clear Cookies file
                    cookies_path = os.path.join(browser_path, 'Cookies')
                    if os.path.exists(cookies_path):
                        # Terminate browser first
                        browser_proc = browser.lower()
                        subprocess.run(
                            f'taskkill /F /IM {browser_proc}.exe',
                            shell=True, capture_output=True, timeout=5
                        )
                        
                        # Backup and clear cookies
                        backup_path = cookies_path + '.backup'
                        if os.path.exists(backup_path):
                            os.remove(backup_path)
                        shutil.copy2(cookies_path, backup_path)
                        open(cookies_path, 'w').close()  # Clear file
                        
                        actions_taken.append(f"{browser} cookies cleared")
                        rollback_instructions.append(
                            f"To restore {browser} cookies, replace {cookies_path} with {backup_path}"
                        )
                        self.logger.info(f"Cleared {browser} cookies")
                        
                except Exception as e:
                    self.logger.warning(f"Could not clear {browser} cookies: {e}")
            
            # Clear Windows credential manager (optional - commented for safety)
            # actions_taken.append("Credential cache cleared")
            
            # Clear DNS cache
            try:
                subprocess.run(
                    'ipconfig /flushdns',
                    shell=True, capture_output=True, timeout=5
                )
                actions_taken.append("DNS cache cleared")
                self.logger.info("DNS cache cleared")
            except Exception as e:
                self.logger.warning(f"Could not clear DNS cache: {e}")
            
            if actions_taken:
                return AutoResponseResult(
                    success=True,
                    action=AutoAction.RESET_SESSION.value,
                    message=f"Session reset complete: {'; '.join(actions_taken)}",
                    rollback_instructions=rollback_instructions + [
                        "You will need to log in to websites again",
                        "Browser history and bookmarks are preserved"
                    ]
                )
            else:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.RESET_SESSION.value,
                    message="No browser sessions could be reset",
                    error="Browsers not found or in use",
                    rollback_instructions=["Manually clear browser cookies in browser settings"]
                )
                
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.RESET_SESSION.value,
                message=f"Session reset failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Manually clear cookies in each browser's settings"]
            )
    
    def execute_clear_cache(self, threat_data: Dict) -> AutoResponseResult:
        """
        Clear temporary files and system cache.
        
        Args:
            threat_data: Threat information
            
        Returns:
            AutoResponseResult with cache clear status
        """
        actions_taken = []
        rollback_instructions = []
        cleared_count = 0
        
        try:
            # Clear Windows Temp folder
            temp_dirs = [
                os.environ.get('TEMP', ''),
                os.environ.get('TMP', ''),
                r'C:\Windows\Temp'
            ]
            
            for temp_dir in temp_dirs:
                if temp_dir and os.path.exists(temp_dir):
                    try:
                        for item in os.listdir(temp_dir):
                            item_path = os.path.join(temp_dir, item)
                            try:
                                if os.path.isfile(item_path):
                                    os.remove(item_path)
                                    cleared_count += 1
                                elif os.path.isdir(item_path):
                                    shutil.rmtree(item_path, ignore_errors=True)
                                    cleared_count += 1
                            except (PermissionError, OSError):
                                pass  # Skip files in use
                        actions_taken.append(f"Cleaned: {temp_dir}")
                        self.logger.info(f"Cleaned temp directory: {temp_dir}")
                    except Exception as e:
                        self.logger.warning(f"Error cleaning {temp_dir}: {e}")
            
            # Clear Windows prefetch (requires admin)
            try:
                prefetch_dir = r'C:\Windows\Prefetch'
                if os.path.exists(prefetch_dir):
                    for item in os.listdir(prefetch_dir):
                        item_path = os.path.join(prefetch_dir, item)
                        try:
                            os.remove(item_path)
                            cleared_count += 1
                        except (PermissionError, OSError):
                            pass
                    actions_taken.append("Prefetch cache cleared")
                    self.logger.info("Prefetch cache cleared")
            except Exception as e:
                self.logger.warning(f"Could not clear prefetch: {e}")
            
            # Clear DNS cache
            try:
                subprocess.run(
                    'ipconfig /flushdns',
                    shell=True, capture_output=True, timeout=5
                )
                actions_taken.append("DNS cache flushed")
            except Exception as e:
                self.logger.warning(f"Could not flush DNS: {e}")
            
            # Clear Windows Store cache
            try:
                subprocess.run(
                    'wsreset.exe',
                    shell=True, capture_output=True, timeout=10
                )
                actions_taken.append("Windows Store cache cleared")
            except Exception as e:
                self.logger.warning(f"Could not clear Windows Store cache: {e}")
            
            if actions_taken:
                return AutoResponseResult(
                    success=True,
                    action=AutoAction.CLEAR_CACHE.value,
                    message=f"Cache cleared: {cleared_count} items removed. {'; '.join(actions_taken)}",
                    rollback_instructions=[
                        "Temporary files will regenerate as needed",
                        "Some applications may start slightly slower until cache rebuilds"
                    ]
                )
            else:
                return AutoResponseResult(
                    success=False,
                    action=AutoAction.CLEAR_CACHE.value,
                    message="No cache could be cleared",
                    error="Access denied or no cache found",
                    rollback_instructions=["Run Disk Cleanup utility manually"]
                )
                
        except Exception as e:
            return AutoResponseResult(
                success=False,
                action=AutoAction.CLEAR_CACHE.value,
                message=f"Cache clear failed: {str(e)}",
                error=str(e),
                rollback_instructions=["Use Windows Disk Cleanup utility"]
            )
    
    def execute_disable_service(self, threat_data: Dict) -> AutoResponseResult:
        """
        Stop and disable Windows services.
        
        Args:
            threat_data: Contains 'service_name' or 'target_services'
            
        Returns:
            AutoResponseResult with service disable status
        """
        services = threat_data.get('target_services', [])
        if not services and threat_data.get('service_name'):
            services = [threat_data['service_name']]
        
        if not services:
            return AutoResponseResult(
                success=False,
                action=AutoAction.DISABLE_SERVICE.value,
                message="No services specified for disable",
                error="No service names provided"
            )
        
        disabled = []
        failed = []
        rollback_instructions = []
        
        for service in services:
            try:
                # Stop the service
                stop_cmd = f'net stop "{service}" /y'
                stop_result = subprocess.run(
                    stop_cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                
                # Disable the service
                disable_cmd = f'sc config "{service}" start= disabled'
                disable_result = subprocess.run(
                    disable_cmd, shell=True, capture_output=True, text=True, timeout=10
                )
                
                if disable_result.returncode == 0:
                    disabled.append(service)
                    self.disabled_services.add(service)
                    self.logger.info(f"Disabled service: {service}")
                    rollback_instructions.append(
                        f'To re-enable {service}, run: sc config "{service}" start= auto && net start "{service}"'
                    )
                else:
                    failed.append((service, disable_result.stderr or "Unknown error"))
                    self.logger.error(f"Failed to disable service {service}: {disable_result.stderr}")
                    
            except subprocess.TimeoutExpired:
                failed.append((service, "Command timeout"))
                self.logger.error(f"Timeout disabling service {service}")
            except Exception as e:
                failed.append((service, str(e)))
                self.logger.error(f"Error disabling service {service}: {e}")
        
        if disabled:
            return AutoResponseResult(
                success=True,
                action=AutoAction.DISABLE_SERVICE.value,
                message=f"Disabled {len(disabled)} service(s): {', '.join(disabled)}",
                rollback_instructions=rollback_instructions
            )
        elif failed:
            return AutoResponseResult(
                success=False,
                action=AutoAction.DISABLE_SERVICE.value,
                message=f"Failed to disable services: {failed}",
                error="Service modification failed - run as Administrator",
                rollback_instructions=[
                    "Run SENTINEL as Administrator",
                    "Use services.msc to manually stop/disable services"
                ]
            )
        else:
            return AutoResponseResult(
                success=True,
                action=AutoAction.DISABLE_SERVICE.value,
                message="Services already disabled or no action needed",
                rollback_instructions=[]
            )
    
    def get_action_history(self, limit: int = 50) -> List[Dict]:
        """Get recent auto-response action history"""
        return self.action_log[-limit:]
    
    def get_quarantined_files(self) -> List[Dict]:
        """Get list of quarantined files"""
        return self.quarantined_files
    
    def get_blocked_ips(self) -> set:
        """Get set of blocked IP addresses"""
        return self.blocked_ips
    
    def rollback_action(self, action_index: int) -> AutoResponseResult:
        """
        Rollback a specific action by index.
        
        Args:
            action_index: Index in action_log to rollback
            
        Returns:
            AutoResponseResult with rollback status
        """
        if action_index < 0 or action_index >= len(self.action_log):
            return AutoResponseResult(
                success=False,
                action="ROLLBACK",
                message=f"Invalid action index: {action_index}",
                error="Index out of range"
            )
        
        action = self.action_log[action_index]
        return AutoResponseResult(
            success=True,
            action="ROLLBACK",
            message=f"Rollback initiated for action: {action['action']}. Follow rollback instructions.",
            rollback_instructions=[
                "Refer to the original action's rollback instructions",
                "Some actions (like process termination) cannot be automatically rolled back"
            ]
        )


# ============================================================================
# RULE ENGINE - Fast Rule-Based Detection for Known Threat Patterns
# ============================================================================

class RuleEngine:
    """
    High-performance rule-based detection engine for known threat patterns.
    Uses signature matching, behavioral analysis, and heuristic rules.
    """

    def __init__(self):
        self.logger = logging.getLogger('SENTINEL.RuleEngine')

        # Known malware name patterns
        self.MALWARE_PATTERNS = {
            'ransomware': ['wannacry', 'cryptolocker', 'locky', 'petya', 'ryuk', 'maze',
                          'encrypt', 'decrypt', '.encrypted', 'cryptowall', 'cerber'],
            'trojan': ['-trojan', 'backdoor', '-rat', 'remote_access', 'c2', 'command_control',
                      'njrat', 'gh0st', 'poison', 'darkcomet', 'blackshades'],
            'spyware': ['keylog', 'screen_capture', 'clipboard_monitor', 'password_steal',
                       '-spy', 'monitor', 'tracker', 'watcher'],
            'rootkit': ['rootkit', 'bootkit', 'driver_hook', 'kernel_hook', 'tdss',
                       'zeroaccess', 'necurs', 'uref'],
            'worm': ['-worm', 'spread', 'propagate', 'network_scan', 'conficker',
                    'blaster', 'sasser', 'mydoom'],
            'adware': ['ad_inject', 'popup', 'browser_hijack', 'genieno', 'fireball',
                      'shopper', 'deals'],
            'cryptominer': ['-miner', 'cryptonight', 'monero', 'bitcoin', 'eth mine',
                           'xmrig', 'minergate', 'nicehash', 'coinhive']
        }

        # Suspicious ports for various attacks
        self.SUSPICIOUS_PORTS = {
            'backdoor': [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345, 54321],
            'iot': [1883, 8883, 5683, 5684, 18880, 8080],  # MQTT, CoAP
            'database': [1433, 3306, 5432, 27017, 6379, 9042],  # MSSQL, MySQL, PostgreSQL, MongoDB, Redis, Cassandra
            'ldap': [389, 636],  # LDAP, LDAPS
        }

        # Fileless malware indicators
        self.FILELESS_INDICATORS = {
            'powershell_suspicious': [
                '-encodedcommand', '-enc', '-hidden', '-windowstyle hidden',
                'invoke-expression', 'iex', 'downloadstring', 'base64',
                'frombase64string', 'webclient', 'httprequest', 'shellcode',
                'virtualalloc', 'createThread', 'memcpy', 'enumprocessmodules'
            ],
            'wmi_suspicious': [
                'win32_process', 'create process', 'execquery', 'select * from',
                'antivirusproduct', 'firewallproduct', 'wmic process call create',
                'processid', 'commandline'
            ],
            'script_hosts': ['wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe',
                            'rundll32.exe', 'installutil.exe', 'regasm.exe', 'msbuild.exe']
        }

        # Command injection patterns
        self.COMMAND_INJECTION_PATTERNS = [
            r'[;&|`$]', r'\|\|', r'&&', r'\$\(', r'`.*`',
            r'/bin/(ba)?sh', r'cmd\.exe', r'powershell',
            r'wget\s+http', r'curl\s+http', r'nc\s+-[el]',
            r'netcat', r'ncat', r'/dev/tcp/', r'/dev/udp/'
        ]

        # Path traversal patterns
        self.PATH_TRAVERSAL_PATTERNS = [
            r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e/',
            r'\.\.%2f', r'%2e%2e\\', r'..%5c', r'%252e%252e%255c',
            r'/etc/passwd', r'/etc/shadow', r'\\windows\\system32',
            r'c:\\windows', r'boot\.ini', r'win\.ini'
        ]

        # XXE injection patterns
        self.XXE_PATTERNS = [
            r'<!ENTITY', r'SYSTEM', r'PUBLIC', r'<!DOCTYPE',
            r'file://', r'expect://', r'php://', r'data://',
            r'input://', r'zip://', r'phar://'
        ]

        # Tech support scam indicators
        self.TECH_SCAM_INDICATORS = [
            'virus detected', 'call microsoft', 'call apple', 'tech support',
            'immediate action', 'computer blocked', 'security alert',
            'warned', 'infected', 'trojan', 'spyware', 'risk',
            'call now', 'do not turn off', 'contact support',
            'microsoft certified', 'apple certified', 'google virus'
        ]

        # Cryptojacking script domains
        self.CRYPTOJACKING_DOMAINS = [
            'coinhive.com', 'coin-hive.com', 'cryptoloot.pro',
            'ppoi.org', 'miner.pr0gramm.com', 'webassembly.stream',
            'minero.cc', 'minero.pw', 'minero.rocks', 'authedmine.com',
            'cryptonight.stream', 'xmr.miner.pr0gramm.com'
        ]

        # Typosquatting patterns for popular domains
        self.TYPOSQUAT_PATTERNS = {
            'google': ['gooogle', 'googel', 'gogle', 'go0gle', 'goog1e'],
            'facebook': ['facebok', 'faceboook', 'fb.com', 'facebook.com'],
            'microsoft': ['microsft', 'micros0ft', 'microsofte', 'rnicrosoft'],
            'apple': ['aple', 'appl3', 'app1e', 'appple'],
            'amazon': ['arnazon', 'amazcn', 'amaz0n', 'amaozn'],
            'paypal': ['paypa1', 'paypaI', 'paypall', 'paypal'],
            'netflix': ['netfliix', 'netflx', 'netfllix', 'n3tflix'],
            'github': ['githbu', 'githube', 'gihtub', 'git-hub']
        }

        # LDAP injection patterns
        self.LDAP_INJECTION_PATTERNS = [
            r'[\(\)\*\\]', r'\x00', r'uid=', r'cn=',
            r'objectClass=', r'malicious.*filter', r'\x0a', r'\x0d'
        ]

        # SSRF indicators
        self.SSRF_INDICATORS = [
            '127.0.0.1', 'localhost', '0.0.0.0', '169.254.169.254',  # AWS metadata
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',  # Private ranges
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', 'metadata.google',
            'http://metadata', 'gcp', 'azure', 'internal'
        ]

        # CSRF indicators
        self.CSRF_INDICATORS = [
            'csrf', 'xsrf', 'anti-forgery', 'requestverification',
            'missing_token', 'token_mismatch', 'invalid_csrf',
            'origin_mismatch', 'referer_missing'
        ]

        # DLL side-loading indicators
        self.DLL_SIDELOADING_INDICATORS = {
            'trusted_apps': ['slack.exe', 'spotify.exe', 'putty.exe', 'winscp.exe',
                           'jitsi.exe', 'signal.exe', 'wire.exe', 'brave.exe'],
            'suspicious_dlls': ['dbghelp.dll', 'version.dll', 'wsock32.dll',
                               'ws2_32.dll', 'cryptbase.dll', 'propsys.dll']
        }

        # Homograph attack characters (Unicode lookalikes)
        self.HOMOGRAPH_CHARS = {
            'a': ['\u0430', '\u0251', '\u1d43'],  # Cyrillic а, Latin alpha
            'c': ['\u0441', '\u03f2'],  # Cyrillic с, Greek lunate sigma
            'e': ['\u0435', '\u03b5'],  # Cyrillic е, Greek epsilon
            'i': ['\u0456', '\u0131'],  # Cyrillic і, Turkish dotless i
            'o': ['\u043e', '\u03bf'],  # Cyrillic о, Greek omicron
            'p': ['\u0440', '\u03c1'],  # Cyrillic р, Greek rho
            'x': ['\u0445', '\u03c7'],  # Cyrillic х, Greek chi
            'y': ['\u0443', '\u04af']   # Cyrillic у
        }

        # Formjacking indicators
        self.FORMJACKING_INDICATORS = [
            'form_data', 'credit_card', 'card_number', 'cvv', 'expiry',
            'exfil', 'keylog', 'input_capture', 'payment_info'
        ]

        # RaaS (Ransomware-as-a-Service) network indicators
        self.RAAS_INDICATORS = [
            'ransom', 'cryptolocker', 'wannacry', 'locky',
            'c2', 'command-control', 'botnet', 'darkweb'
        ]

        # Double extortion ransomware patterns
        self.DOUBLE_EXTORTION_PATTERNS = [
            'encrypt', 'exfil', 'leak', 'darkweb', 'ransom'
        ]

        # Wiper malware destructive commands
        self.WIPER_COMMANDS = [
            'del /s', 'del /q', 'format', 'cipher /w', 'sdelete',
            'shred', 'rm -rf', 'dd if=/dev/zero', 'mkfs'
        ]

        # Dead man's switch beacon intervals (seconds)
        self.DEAD_MANS_BEACON_INTERVALS = [60, 300, 600, 3600, 7200]

        # Watering hole indicators
        self.WATERING_HOLE_DOMAINS = [
            'update-flash', 'java-update', 'codec-download',
            'free-download', 'crack', 'keygen', 'torrent'
        ]

    def analyze(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Main analysis method - orchestrates all detection modules.

        Args:
            snapshot: System snapshot containing system, processes, network, security data

        Returns:
            List of detected threat dictionaries
        """
        threats = []
        system = snapshot.get("system", {}) or {}
        processes = snapshot.get("processes", []) or []
        network = snapshot.get("network", {}) or {}
        security = snapshot.get("security", {}) or {}

        try:
            # Category 1: Malware Detection
            threats.extend(self._detect_malware(processes, system))

            # Category 2: Social Engineering Detection
            threats.extend(self._detect_social_engineering(processes, security, network))

            # Category 3: Network Attacks Detection
            threats.extend(self._detect_network_attacks(network, processes))

            # Category 4: Code Injection Detection
            threats.extend(self._detect_code_injection(processes, network))

            # Category 5: Fileless & Advanced Attacks
            threats.extend(self._detect_fileless_attacks(processes, system))

            # Category 6: Web-Based Threats
            threats.extend(self._detect_web_threats(processes, network))

            # Category 7: Data Theft Detection
            threats.extend(self._detect_data_theft(processes, network))

            # Category 8: Unauthorized Access Detection
            threats.extend(self._detect_unauthorized_access(processes, security, network))

            # Category 9: Harm & Disruption Detection
            threats.extend(self._detect_harm_disruption(system, processes))

            # Category 10: Infrastructure Exploitation
            threats.extend(self._detect_infrastructure_exploitation(processes, security, network))

            # Category 11: Advanced Persistent Threats
            threats.extend(self._detect_advanced_threats(processes, system, security))

        except Exception as e:
            self.logger.error(f"Error during rule engine analysis: {e}")
            threats.append({
                "type": "DETECTION_ERROR",
                "severity": "MEDIUM",
                "confidence": 100,
                "description": f"Detection engine encountered an error: {str(e)}",
                "preventive_steps": ["Restart the detection service", "Check system logs", "Update SENTINEL"],
                "auto_action": "ALERT_ONLY"
            })

        return threats

    def _detect_malware(self, processes: List[Dict], system: Dict) -> List[Dict]:
        """
        Detect malware: Viruses, Worms, Trojans, Ransomware, Spyware, Rootkits, Adware

        Args:
            processes: List of running process dictionaries
            system: System metrics dictionary

        Returns:
            List of malware threat dictionaries
        """
        threats = []

        import re
        for proc in processes:
            name = (proc.get('name') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()
            cpu = proc.get('cpu_percent', 0) or 0
            risk_score = proc.get('risk_score', 0) or 0

            for malware_type, patterns in self.MALWARE_PATTERNS.items():
                matched_pattern = False
                for pattern in patterns:
                    if pattern.startswith('-'):
                        regex = r'\b' + re.escape(pattern[1:]) + r'\b'
                        if re.search(regex, name) or re.search(regex, exe_path):
                            matched_pattern = True
                            break
                    else:
                        if pattern in name or pattern in exe_path:
                            matched_pattern = True
                            break
                            
                if matched_pattern:
                    # Skip known safe processes unless risk score is very high
                    if proc.get('is_known', False) and risk_score < 80:
                        continue
                        
                    severity = 'CRITICAL' if malware_type in ['ransomware', 'rootkit', 'trojan'] else 'HIGH'
                    threats.append({
                        "type": f"{malware_type.upper()}_DETECTED",
                        "severity": severity,
                        "confidence": min(95, 70 + len(patterns) * 5),
                        "description": f"Malicious process '{proc.get('name', 'unknown')}' detected. Indicators match {malware_type} signature.",
                        "processes": [proc.get('name', 'unknown')],
                        "exe_path": proc.get('exe_path'),
                        "pid": proc.get('pid'),
                        "preventive_steps": self._get_malware_steps(malware_type),
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc.get('pid')]
                    })

        # Ransomware-specific: Mass file encryption detection
        high_disk_activity = system.get('disk_percent', 0) > 90
        high_cpu_with_encryption = any(
            p.get('cpu_percent', 0) > 80 and 'encrypt' in (p.get('name') or '').lower()
            for p in processes
        )
        if high_disk_activity and high_cpu_with_encryption:
            threats.append({
                "type": "RANSOMWARE_ACTIVITY",
                "severity": "CRITICAL",
                "confidence": 95,
                "description": "Ransomware-like behavior detected: High disk activity with encryption processes running",
                "preventive_steps": [
                    "IMMEDIATELY disconnect from network and internet",
                    "Force shutdown the system to prevent further encryption",
                    "Do NOT pay the ransom - there's no guarantee of file recovery",
                    "Boot from clean recovery media and backup unencrypted files",
                    "Run offline antivirus scan before rebooting normally",
                    "Restore files from clean backup if available",
                    "Report to cybercrime authorities",
                    "Identify ransomware variant using ID Ransomware service"
                ],
                "auto_action": "EMERGENCY_SHUTDOWN",
                "target_pids": []
            })

        return threats

    def _detect_social_engineering(self, processes: List[Dict], security: Dict, network: Dict) -> List[Dict]:
        """
        Detect social engineering: Phishing, Baiting, Infostealer, Tech Support Scam
        """
        threats = []

        browser_processes = [
            p for p in processes
            if any(b in (p.get('name') or '').lower() for b in ['chrome', 'firefox', 'edge', 'browser', 'electron'])
        ]

        # Baiting attack - Unknown USB devices
        usb_devices = security.get('usb_devices', [])
        suspicious_usb = [d for d in usb_devices if 'unknown' in (d.get('device') or '').lower()]

        if suspicious_usb:
            threats.append({
                "type": "BAITING_ATTACK_INDICATOR",
                "severity": "HIGH",
                "confidence": 75,
                "description": f"Unknown USB device(s) detected: {[d['device'] for d in suspicious_usb]}. Possible baiting attack.",
                "preventive_steps": [
                    "IMMEDIATELY remove the suspicious USB device",
                    "Do NOT open any files from the USB drive",
                    "Run antivirus scan on the USB device",
                    "Check if USB autorun was triggered",
                    "Review recently opened files for malware",
                    "Enable USB device control policies",
                    "Educate users about baiting attacks",
                    "Report to IT security team"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Infostealer - Screen capture during browser use
        # Explicit blacklist of acceptable screen terms in common process names
        safe_screen_procs = ['smartscreen.exe', 'shellexperiencehost.exe', 'startmenuexperiencehost.exe', 'obs64.exe']
        screen_capture_procs = [
            p for p in processes
            if any(s in (p.get('name') or '').lower() for s in ['screen', 'capture', 'record', 'screenshot'])
            and p.get('name', '').lower() not in safe_screen_procs
            and not p.get('is_known', False)
        ]

        if screen_capture_procs and browser_processes:
            threats.append({
                "type": "INFOSTEALER_INDICATOR",
                "severity": "CRITICAL",
                "confidence": 80,
                "description": "Screen capture process active while browser is running. Possible credential harvesting.",
                "preventive_steps": [
                    "Close all browser windows with sensitive data (banking, email)",
                    "Terminate the screen capture process immediately",
                    "Change all passwords from a different, clean device",
                    "Enable two-factor authentication on all accounts",
                    "Check browser extensions for malicious add-ons",
                    "Run full antivirus scan",
                    "Monitor accounts for unauthorized access",
                    "Review recently installed software"
                ],
                "auto_action": "SUSPEND_PROCESS",
                "target_pids": [p['pid'] for p in screen_capture_procs[:3]]
            })

        # Tech Support Scam Detection
        for proc in browser_processes:
            if any(scams in (proc.get('name') or '').lower() for scams in self.TECH_SCAM_INDICATORS):
                threats.append({
                    "type": "TECH_SUPPORT_SCAM_DETECTED",
                    "severity": "HIGH",
                    "confidence": 70,
                    "description": "Browser displaying potential tech support scam content. Fake alert page detected.",
                    "preventive_steps": [
                        "DO NOT call any phone numbers displayed",
                        "DO NOT click any buttons or links on the page",
                        "Close the browser tab/window immediately (use Task Manager if needed)",
                        "Clear browser cache and cookies",
                        "Run antivirus scan to check for malware",
                        "Enable pop-up blocker in browser",
                        "Install ad-blocker extension",
                        "Report the scam page to browser vendor"
                    ],
                    "auto_action": "ALERT_ONLY",
                    "target_pids": [proc['pid']]
                })

        # Phishing indicators
        connections = network.get('connections', [])
        suspicious_phishing = [
            c for c in connections
            if c.get('remote_port') in [80, 443] and c.get('is_suspicious', False)
        ]

        if len(suspicious_phishing) > 5 and browser_processes:
            threats.append({
                "type": "PHISHING_INDICATOR",
                "severity": "MEDIUM",
                "confidence": 65,
                "description": "Multiple suspicious web connections detected. Possible phishing activity.",
                "preventive_steps": [
                    "Do NOT click links in suspicious emails",
                    "Verify sender authenticity",
                    "Check URL carefully for typos",
                    "Enable email filtering",
                    "Report phishing attempts",
                    "Educate users about phishing",
                    "Use anti-phishing tools",
                    "Enable spam filters"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        return threats

    def _detect_network_attacks(self, network: Dict, processes: List[Dict]) -> List[Dict]:
        """
        Detect network attacks: DDoS, MITM, DNS Spoofing, SSRF
        """
        threats = []
        connections = network.get('connections', [])
        bytes_sent = network.get('bytes_sent', 0)
        bytes_recv = network.get('bytes_recv', 0)

        # DDoS indicator
        if bytes_sent > 10000000000 or bytes_recv > 10000000000: # Increased to 10GB for modern usage
            threats.append({
                "type": "DDOS_ATTACK_INDICATOR",
                "severity": "HIGH",
                "confidence": 70,
                "description": f"Extremely high network traffic detected (Sent: {bytes_sent/1000000:.1f}MB, Recv: {bytes_recv/1000000:.1f}MB). Possible DDoS participation or attack.",
                "preventive_steps": [
                    "Disconnect from internet immediately",
                    "Check which process is generating traffic",
                    "Block suspicious outbound connections in firewall",
                    "Contact ISP if under DDoS attack",
                    "Enable DDoS protection if running a server",
                    "Check for botnet infection",
                    "Run full malware scan",
                    "Monitor network traffic patterns"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # MITM indicator
        mitm_ports = [80, 443, 8080, 8443]
        mitm_connections = [c for c in connections if c.get('remote_port') in mitm_ports]

        if len(mitm_connections) > 100: # Increased from 10 to 100 allowing standard web browsing
            threats.append({
                "type": "MITM_ATTACK_INDICATOR",
                "severity": "HIGH",
                "confidence": 65,
                "description": f"Multiple HTTP/HTTPS connections detected ({len(mitm_connections)}). Possible Man-in-the-Middle attack or compromised network.",
                "preventive_steps": [
                    "Verify you're on a trusted network",
                    "Check if HTTPS is being downgraded to HTTP",
                    "Look for certificate warnings in browser",
                    "Use VPN for sensitive transactions",
                    "Avoid public Wi-Fi for banking/shopping",
                    "Check ARP table for spoofing (arp -a)",
                    "Enable HTTPS Everywhere browser extension",
                    "Monitor for DNS changes"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # DNS Spoofing indicator
        dns_connections = [c for c in connections if c.get('remote_port') == 53]
        if len(dns_connections) > 20:
            threats.append({
                "type": "DNS_SPOOFING_INDICATOR",
                "severity": "MEDIUM",
                "confidence": 60,
                "description": f"Excessive DNS queries detected ({len(dns_connections)}). Possible DNS spoofing or cache poisoning attempt.",
                "preventive_steps": [
                    "Change DNS server to trusted provider (Google: 8.8.8.8, Cloudflare: 1.1.1.1)",
                    "Clear DNS cache (ipconfig /flushdns)",
                    "Check hosts file for unauthorized entries",
                    "Use DNS over HTTPS (DoH) or DNS over TLS (DoT)",
                    "Verify website certificates",
                    "Run antivirus scan",
                    "Check router DNS settings",
                    "Enable DNSSEC if available"
                ],
                "auto_action": "CLEAR_CACHE",
                "target_pids": []
            })

        # SSRF Detection
        # Exclude localhost/loopback IPs (these are the app's own connections, not SSRF)
        SSRF_SAFE_IPS = {'127.0.0.1', 'localhost', '0.0.0.0', '::1'}
        ssrf_seen_ips = set()  # Deduplicate: only report each IP once per scan
        for conn in connections:
            remote_ip = conn.get('remote_ip') or ''
            # Skip empty, safe (self-connection), or already-reported IPs
            if not remote_ip or remote_ip in SSRF_SAFE_IPS or remote_ip in ssrf_seen_ips:
                continue
            for ssrf_indicator in self.SSRF_INDICATORS:
                # Skip indicators that match safe IPs
                if ssrf_indicator in SSRF_SAFE_IPS:
                    continue
                if ssrf_indicator in remote_ip:
                    ssrf_seen_ips.add(remote_ip)
                    threats.append({
                        "type": "SSRF_ATTACK_INDICATOR",
                        "severity": "HIGH",
                        "confidence": 75,
                        "description": f"Server-Side Request Forgery indicator: Connection to internal/metadata IP ({remote_ip}). Possible SSRF exploitation.",
                        "preventive_steps": [
                            "Block outbound connections to internal IP ranges",
                            "Validate and sanitize all user-supplied URLs",
                            "Use allowlists for permitted external services",
                            "Disable unnecessary URL schemes (file://, gopher://)",
                            "Implement network segmentation",
                            "Monitor for cloud metadata access attempts",
                            "Review application logs for SSRF patterns",
                            "Apply security patches to web frameworks"
                        ],
                        "auto_action": "ALERT_ONLY",
                        "target_ips": [remote_ip]
                    })
                    break

        return threats

    def _detect_code_injection(self, processes: List[Dict], network: Dict) -> List[Dict]:
        """
        Detect code injection: SQL Injection, XSS, Command Injection, LDAP Injection, XXE
        """
        threats = []

        # SQL Injection indicators
        db_processes = [
            p for p in processes
            if any(db in (p.get('name') or '').lower()
                  for db in ['sqlservr', 'mysqld', 'postgres', 'mongod', 'redis'])
        ]

        for proc in db_processes:
            exe_path = (proc.get('exe_path') or '').lower()
            if any(bad in exe_path for bad in ['\\temp\\', '\\appdata\\', '\\downloads\\']):
                threats.append({
                    "type": "SQL_INJECTION_EXPLOITATION",
                    "severity": "CRITICAL",
                    "confidence": 88,
                    "description": f"Database process '{proc['name']}' running from suspicious location. Possible SQL injection exploitation.",
                    "processes": [proc['name']],
                    "exe_path": proc.get('exe_path'),
                    "preventive_steps": [
                        "IMMEDIATELY isolate system from network",
                        "Stop the suspicious database process",
                        "Check web application logs for SQL injection patterns",
                        "Review database for unauthorized data access",
                        "Enable parameterized queries in all code",
                        "Deploy Web Application Firewall (WAF)",
                        "Audit all database queries from last 24 hours",
                        "Check for data exfiltration"
                    ],
                    "auto_action": "ISOLATE_AND_ALERT",
                    "target_pids": [proc['pid']]
                })

        # XSS indicator
        browser_procs = [
            p for p in processes
            if any(b in (p.get('name') or '').lower() for b in ['chrome', 'firefox', 'edge', 'browser'])
        ]
        script_procs = [
            p for p in processes
            if any(s in (p.get('name') or '').lower() for s in ['node', 'python', 'powershell', 'wscript', 'cscript'])
        ]

        if browser_procs and script_procs:
            script_network = [
                c for c in network.get('connections', [])
                if c.get('pid') in [p['pid'] for p in script_procs]
            ]

            if len(script_network) > 5:
                threats.append({
                    "type": "XSS_ATTACK_INDICATOR",
                    "severity": "HIGH",
                    "confidence": 70,
                    "description": "Script execution processes active with browser. Possible Cross-Site Scripting (XSS) attack.",
                    "preventive_steps": [
                        "Close all browser tabs with sensitive data",
                        "Clear browser cache and cookies",
                        "Check browser extensions for malicious scripts",
                        "Review recently visited websites",
                        "Enable Content Security Policy (CSP) headers",
                        "Use script-blocking browser extensions",
                        "Run antivirus scan",
                        "Monitor for session hijacking"
                    ],
                    "auto_action": "RESET_SESSION",
                    "target_pids": [p['pid'] for p in script_procs[:3]]
                })

        # Command Injection Detection
        for proc in processes:
            cmd_line = (proc.get('command_line') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()

            for pattern in self.COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, cmd_line, re.IGNORECASE):
                    threats.append({
                        "type": "COMMAND_INJECTION_DETECTED",
                        "severity": "CRITICAL",
                        "confidence": 85,
                        "description": f"Command injection pattern detected in process '{proc['name']}'. Suspicious command-line arguments found.",
                        "processes": [proc['name']],
                        "exe_path": exe_path,
                        "preventive_steps": [
                            "IMMEDIATELY terminate the suspicious process",
                            "Disconnect from network",
                            "Check for spawned child processes",
                            "Review application input validation",
                            "Sanitize all user-supplied input",
                            "Use allowlists for permitted commands",
                            "Implement proper input encoding",
                            "Enable application logging and monitoring"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })
                    break

        # LDAP Injection Detection
        for proc in processes:
            cmd_line = proc.get('command_line') or ''
            for pattern in self.LDAP_INJECTION_PATTERNS:
                if re.search(pattern, cmd_line):
                    threats.append({
                        "type": "LDAP_INJECTION_DETECTED",
                        "severity": "HIGH",
                        "confidence": 75,
                        "description": f"LDAP injection pattern detected in process '{proc['name']}'. Malicious LDAP query attempted.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "Terminate the suspicious process",
                            "Validate and sanitize LDAP input",
                            "Use parameterized LDAP queries",
                            "Implement input allowlisting",
                            "Escape special LDAP characters",
                            "Apply least privilege to LDAP accounts",
                            "Enable LDAP query logging",
                            "Review LDAP access controls"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })
                    break

        # XXE Injection Detection
        for proc in processes:
            cmd_line = proc.get('command_line') or ''
            exe_name = (proc.get('name') or '').lower()

            if any(xml_app in exe_name for xml_app in ['java', 'python', 'php', 'node']):
                for pattern in self.XXE_PATTERNS:
                    if re.search(pattern, cmd_line, re.IGNORECASE):
                        threats.append({
                            "type": "XXE_INJECTION_DETECTED",
                            "severity": "HIGH",
                            "confidence": 80,
                            "description": f"XXE (XML External Entity) injection pattern detected in '{proc['name']}'. External entity resolution attempted.",
                            "processes": [proc['name']],
                            "preventive_steps": [
                                "Disable external entity processing in XML parser",
                                "Use JSON instead of XML where possible",
                                "Update XML parsing libraries",
                                "Implement input validation",
                                "Use allowlists for permitted entities",
                                "Apply security patches to XML processors",
                                "Monitor for file access attempts",
                                "Review application XML handling code"
                            ],
                            "auto_action": "SUSPEND_PROCESS",
                            "target_pids": [proc['pid']]
                        })
                        break

        # Zero-Day indicator
        unknown_high_risk = [
            p for p in processes
            if p.get('risk_score', 0) > 80
            and not p.get('is_known', True)
            and p.get('cpu_percent', 0) > 50
        ]

        if unknown_high_risk:
            threats.append({
                "type": "ZERO_DAY_EXPLOIT_INDICATOR",
                "severity": "CRITICAL",
                "confidence": 75,
                "description": f"Unknown high-risk process '{unknown_high_risk[0]['name']}' with unusual behavior. Possible zero-day exploit.",
                "processes": [p['name'] for p in unknown_high_risk[:3]],
                "preventive_steps": [
                    "IMMEDIATELY terminate the suspicious process",
                    "Disconnect from network",
                    "Create memory dump for analysis (if possible)",
                    "Check for similar unknown processes",
                    "Review system logs for exploitation attempts",
                    "Update all software to latest versions",
                    "Enable enhanced security monitoring",
                    "Report to security vendor for analysis"
                ],
                "auto_action": "SUSPEND_PROCESS",
                "target_pids": [p['pid'] for p in unknown_high_risk[:3]]
            })

        return threats

    def _detect_fileless_attacks(self, processes: List[Dict], system: Dict) -> List[Dict]:
        """
        Detect fileless malware: PowerShell/WMI abuse, script-based attacks
        """
        threats = []

        for proc in processes:
            name = (proc.get('name') or '').lower()
            cmd_line = (proc.get('command_line') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()
            cpu = proc.get('cpu_percent', 0)
            risk_score = proc.get('risk_score', 0)

            # Fileless Malware - PowerShell
            if 'powershell' in name or 'pwsh' in name:
                for indicator in self.FILELESS_INDICATORS['powershell_suspicious']:
                    if indicator in cmd_line:
                        threats.append({
                            "type": "FILELESS_MALWARE_DETECTED",
                            "severity": "CRITICAL",
                            "confidence": 85,
                            "description": f"Fileless malware indicator in PowerShell: '{indicator}' detected. Possible in-memory attack.",
                            "processes": [proc['name']],
                            "exe_path": exe_path,
                            "pid": proc['pid'],
                            "preventive_steps": [
                                "IMMEDIATELY terminate the PowerShell process",
                                "Enable PowerShell Script Block Logging",
                                "Enable PowerShell Module Logging",
                                "Constrain PowerShell to constrained language mode",
                                "Block execution of encoded commands",
                                "Monitor for suspicious PowerShell activity",
                                "Update Windows Defender signatures",
                                "Review PowerShell execution policies"
                            ],
                            "auto_action": "SUSPEND_PROCESS",
                            "target_pids": [proc['pid']]
                        })
                        break

            # Fileless Malware - WMI abuse
            if 'wmic' in name or 'wmi' in cmd_line or 'winmgmt' in name:
                for indicator in self.FILELESS_INDICATORS['wmi_suspicious']:
                    if indicator in cmd_line:
                        threats.append({
                            "type": "FILELESS_MALWARE_WMI_ABUSE",
                            "severity": "HIGH",
                            "confidence": 80,
                            "description": f"WMI abuse detected: '{indicator}' found in command line. Possible fileless persistence.",
                            "processes": [proc['name']],
                            "exe_path": exe_path,
                            "pid": proc['pid'],
                            "preventive_steps": [
                                "Terminate the WMI process",
                                "Check WMI event subscriptions for persistence",
                                "Review WMI repository for malicious classes",
                                "Disable WMI if not needed",
                                "Monitor WMI activity with Sysmon",
                                "Apply WMI security best practices",
                                "Check for lateral movement attempts",
                                "Review Windows event logs"
                            ],
                            "auto_action": "SUSPEND_PROCESS",
                            "target_pids": [proc['pid']]
                        })
                        break

            # Fileless Malware - Script hosts
            if any(host in name for host in self.FILELESS_INDICATORS['script_hosts']):
                if risk_score > 60 or cpu > 50:
                    threats.append({
                        "type": "FILELESS_MALWARE_SCRIPT_HOST",
                        "severity": "HIGH",
                        "confidence": 75,
                        "description": f"Suspicious script host activity: '{proc['name']}' with high risk score. Possible fileless execution.",
                        "processes": [proc['name']],
                        "exe_path": exe_path,
                        "pid": proc['pid'],
                        "preventive_steps": [
                            "Terminate the script host process",
                            "Review script files being executed",
                            "Check for malicious VBScript/JScript files",
                            "Disable Windows Script Host if not needed",
                            "Enable script execution logging",
                            "Block script hosts via AppLocker",
                            "Scan for malicious script files",
                            "Monitor for LOLBIN abuse"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })

        return threats

    def _detect_web_threats(self, processes: List[Dict], network: Dict) -> List[Dict]:
        """
        Detect web-based threats: Cryptojacking, Drive-by Download, CSRF, Typosquatting
        """
        threats = []
        connections = network.get('connections', [])

        browser_procs = [
            p for p in processes
            if any(b in (p.get('name') or '').lower() for b in ['chrome', 'firefox', 'edge', 'brave', 'opera'])
        ]

        # Web-based Cryptojacking Detection
        for proc in browser_procs:
            cpu = proc.get('cpu_percent', 0)

            if cpu > 80:
                crypto_connections = [
                    c for c in connections
                    if c.get('pid') == proc['pid'] and
                    any(domain in (c.get('remote_ip') or '').lower() for domain in self.CRYPTOJACKING_DOMAINS)
                ]

                if crypto_connections or cpu > 90:
                    threats.append({
                        "type": "WEB_CRYPTOJACKING_DETECTED",
                        "severity": "HIGH",
                        "confidence": 75 if crypto_connections else 60,
                        "description": f"Browser '{proc['name']}' showing cryptojacking behavior (CPU: {cpu}%). Mining script likely executing.",
                        "processes": [proc['name']],
                        "pid": proc['pid'],
                        "preventive_steps": [
                            "Close the affected browser tab immediately",
                            "Install anti-cryptojacking browser extension",
                            "Enable NoScript or similar script blocker",
                            "Clear browser cache and cookies",
                            "Update browser to latest version",
                            "Avoid visiting suspicious websites",
                            "Use ad-blocker to block mining scripts",
                            "Monitor CPU usage for future incidents"
                        ],
                        "auto_action": "ALERT_ONLY",
                        "target_pids": [proc['pid']]
                    })

        # Drive-by Download Detection
        for proc in browser_procs:
            exe_path = (proc.get('exe_path') or '').lower()
            risk_score = proc.get('risk_score', 0)

            if risk_score > 70 and not proc.get('is_known', True):
                threats.append({
                    "type": "DRIVE_BY_DOWNLOAD_DETECTED",
                    "severity": "HIGH",
                    "confidence": 70,
                    "description": f"Possible drive-by download detected in browser '{proc['name']}'. Suspicious file download without user interaction.",
                    "processes": [proc['name']],
                    "preventive_steps": [
                        "Close the browser immediately",
                        "Do NOT open any downloaded files",
                        "Check Downloads folder for suspicious files",
                        "Delete any suspicious downloads",
                        "Run full antivirus scan",
                        "Clear browser cache and history",
                        "Update browser and plugins",
                        "Enable download warnings in browser"
                    ],
                    "auto_action": "ALERT_ONLY",
                    "target_pids": [proc['pid']]
                })

        # CSRF Detection
        for proc in browser_procs:
            cmd_line = (proc.get('command_line') or '').lower()

            for indicator in self.CSRF_INDICATORS:
                if indicator in cmd_line:
                    threats.append({
                        "type": "CSRF_ATTACK_INDICATOR",
                        "severity": "MEDIUM",
                        "confidence": 65,
                        "description": f"CSRF (Cross-Site Request Forgery) indicator detected in browser activity. Unauthorized request may have been submitted.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "Log out of sensitive websites (banking, email)",
                            "Clear browser cookies and session data",
                            "Check account activity for unauthorized actions",
                            "Enable SameSite cookie attribute",
                            "Use CSRF tokens in web applications",
                            "Implement request origin validation",
                            "Use separate browsers for sensitive/non-sensitive sites",
                            "Enable browser security extensions"
                        ],
                        "auto_action": "CLEAR_CACHE",
                        "target_pids": [proc['pid']]
                    })
                    break

        # Typosquatting Detection
        for conn in connections:
            remote_ip = (conn.get('remote_ip') or '').lower()

            for legitimate, typos in self.TYPOSQUAT_PATTERNS.items():
                for typo in typos:
                    if typo in remote_ip:
                        threats.append({
                            "type": "TYPOSQUATTING_DETECTED",
                            "severity": "MEDIUM",
                            "confidence": 70,
                            "description": f"Possible typosquatting domain detected. Connection to '{remote_ip}' may be impersonating '{legitimate}'.",
                            "preventive_steps": [
                                "Verify the URL carefully before entering data",
                                "Check for HTTPS and valid certificate",
                                "Type URLs manually instead of clicking links",
                                "Use bookmark for frequently visited sites",
                                "Enable browser safe browsing features",
                                "Install anti-phishing extensions",
                                "Report typosquatting domain to authorities",
                                "Educate users about typosquatting risks"
                            ],
                            "auto_action": "BLOCK_IP",
                            "target_ips": [remote_ip]
                        })
                        break

        # Homograph Attack Detection
        for conn in connections:
            remote_ip = (conn.get('remote_ip') or '')
            for char, lookalikes in self.HOMOGRAPH_CHARS.items():
                if any(lookalike in remote_ip for lookalike in lookalikes):
                    threats.append({
                        "type": "HOMOGRAPH_ATTACK_DETECTED",
                        "severity": "HIGH",
                        "confidence": 75,
                        "description": f"Homograph attack detected: Unicode lookalike characters in domain '{remote_ip}'.",
                        "preventive_steps": [
                            "Do NOT enter any credentials on this website",
                            "Verify the domain using Punycode decoder",
                            "Check for HTTPS and valid certificate",
                            "Type URLs manually instead of clicking links",
                            "Enable browser IDN display options",
                            "Use security extensions that detect homographs",
                            "Report the malicious domain",
                            "Educate users about homograph attacks"
                        ],
                        "auto_action": "BLOCK_IP",
                        "target_ips": [remote_ip]
                    })
                    break

        # Watering Hole Detection
        for conn in connections:
            remote_ip = (conn.get('remote_ip') or '').lower()
            for indicator in self.WATERING_HOLE_DOMAINS:
                if indicator in remote_ip:
                    threats.append({
                        "type": "WATERING_HOLE_ATTACK_DETECTED",
                        "severity": "HIGH",
                        "confidence": 70,
                        "description": f"Connection to suspicious domain '{remote_ip}'. Possible watering hole attack.",
                        "preventive_steps": [
                            "Close the browser immediately",
                            "Do NOT download any files from this site",
                            "Clear browser cache and cookies",
                            "Run antivirus scan",
                            "Check for unauthorized software installations",
                            "Review browser extensions",
                            "Avoid visiting compromised websites",
                            "Report the malicious domain"
                        ],
                        "auto_action": "ALERT_ONLY",
                        "target_pids": []
                    })
                    break

        # QR Code Phishing (Quishing) Detection
        for proc in browser_procs:
            cmd_line = (proc.get('command_line') or '').lower()
            if 'qr' in cmd_line or 'qrcode' in cmd_line or 'scan' in cmd_line:
                if proc.get('risk_score', 0) > 50:
                    threats.append({
                        "type": "QR_CODE_PHISHING_DETECTED",
                        "severity": "MEDIUM",
                        "confidence": 60,
                        "description": f"Possible QR code phishing (quishing) activity in '{proc['name']}'.",
                        "preventive_steps": [
                            "Do NOT scan QR codes from untrusted sources",
                            "Verify the destination URL before proceeding",
                            "Do NOT enter credentials after scanning QR codes",
                            "Use QR scanner with URL preview",
                            "Be wary of QR codes in emails",
                            "Check for HTTPS on landing pages",
                            "Report suspicious QR codes",
                            "Educate users about quishing attacks"
                        ],
                        "auto_action": "ALERT_ONLY",
                        "target_pids": [proc['pid']]
                    })

        # Formjacking Detection
        for proc in browser_procs:
            cmd_line = (proc.get('command_line') or '').lower()
            for indicator in self.FORMJACKING_INDICATORS:
                if indicator in cmd_line:
                    threats.append({
                        "type": "FORMJACKING_DETECTED",
                        "severity": "CRITICAL",
                        "confidence": 80,
                        "description": f"Formjacking indicator detected in '{proc['name']}'. Form data may be exfiltrated.",
                        "preventive_steps": [
                            "Do NOT enter any payment information",
                            "Close the browser immediately",
                            "Check browser extensions for malicious scripts",
                            "Monitor credit card statements",
                            "Use virtual credit cards for online purchases",
                            "Enable transaction alerts",
                            "Report the compromised website",
                            "Consider identity protection services"
                        ],
                        "auto_action": "RESET_SESSION",
                        "target_pids": [proc['pid']]
                    })
                    break

        return threats

    def _detect_data_theft(self, processes: List[Dict], network: Dict) -> List[Dict]:
        """
        Detect data theft: Infostealer, Packet Sniffing, Data Exfiltration, Session Hijacking
        """
        threats = []
        connections = network.get('connections', [])

        # Infostealer - Processes accessing browser data
        browser_data_access = [
            p for p in processes
            if any(b in (p.get('exe_path') or '').lower() for b in ['chrome', 'firefox', 'edge', 'browser'])
            and not any(b in (p.get('name') or '').lower() for b in ['chrome', 'firefox', 'edge'])
        ]

        if browser_data_access:
            threats.append({
                "type": "INFOSTEALER_DETECTED",
                "severity": "CRITICAL",
                "confidence": 85,
                "description": "Process accessing browser data files. Possible password/cookie stealer.",
                "processes": [p['name'] for p in browser_data_access[:3]],
                "preventive_steps": [
                    "IMMEDIATELY terminate suspicious processes",
                    "Change all passwords from a clean device",
                    "Enable two-factor authentication everywhere",
                    "Clear browser saved passwords",
                    "Check for unauthorized account access",
                    "Monitor financial accounts",
                    "Run full antivirus scan",
                    "Consider identity protection service"
                ],
                "auto_action": "SUSPEND_PROCESS",
                "target_pids": [p['pid'] for p in browser_data_access[:3]]
            })

        # Packet Sniffing
        network_monitors = [
            p for p in processes
            if any(m in (p.get('name') or '').lower() for m in ['wireshark', 'tcpdump', 'packet', 'sniffer', 'network monitor'])
        ]

        if network_monitors:
            threats.append({
                "type": "PACKET_SNIFFING_DETECTED",
                "severity": "HIGH",
                "confidence": 80,
                "description": "Network monitoring/packet capture tool detected. Possible eavesdropping.",
                "processes": [p['name'] for p in network_monitors],
                "preventive_steps": [
                    "Verify if network monitoring is authorized",
                    "Terminate unauthorized monitoring tools",
                    "Use encryption (HTTPS, VPN) for all sensitive traffic",
                    "Check network adapter for promiscuous mode",
                    "Review who installed the monitoring software",
                    "Enable network encryption",
                    "Monitor for captured data leaks",
                    "Report to IT security if unauthorized"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": [p['pid'] for p in network_monitors]
            })

        # Data Exfiltration
        outbound_by_ip = {}
        for conn in connections:
            ip = conn.get('remote_ip')
            if ip:
                outbound_by_ip[ip] = outbound_by_ip.get(ip, 0) + 1

        suspicious_ips = [ip for ip, count in outbound_by_ip.items() if count > 10]
        if suspicious_ips:
            threats.append({
                "type": "DATA_EXFILTRATION_INDICATOR",
                "severity": "CRITICAL",
                "confidence": 78,
                "description": f"High volume connections to external IP(s): {suspicious_ips[:3]}. Possible data theft.",
                "preventive_steps": [
                    "IMMEDIATELY disconnect from internet",
                    "Block suspicious IPs in firewall",
                    "Identify which process is sending data",
                    "Check what data may have been stolen",
                    "Preserve logs for investigation",
                    "Notify affected parties if data breached",
                    "Report to cybercrime authorities",
                    "Enable data loss prevention (DLP) tools"
                ],
                "auto_action": "BLOCK_IP",
                "target_ips": suspicious_ips[:5]
            })

        # Session Hijacking
        session_anomalies = []
        for proc in processes:
            name = (proc.get('name') or '').lower()
            if any(s in name for s in ['cookie', 'session', 'token', 'auth']):
                if not proc.get('is_known', True):
                    session_anomalies.append(proc)

        if session_anomalies:
            threats.append({
                "type": "SESSION_HIJACKING_INDICATOR",
                "severity": "HIGH",
                "confidence": 70,
                "description": f"Processes accessing session/cookie data detected: {[p['name'] for p in session_anomalies[:3]]}. Possible session hijacking.",
                "processes": [p['name'] for p in session_anomalies[:3]],
                "preventive_steps": [
                    "Log out of all sensitive websites immediately",
                    "Clear all browser cookies and session data",
                    "Change passwords for affected accounts",
                    "Enable secure and HttpOnly cookie flags",
                    "Implement session timeout policies",
                    "Use SameSite cookie attribute",
                    "Monitor for unauthorized account access",
                    "Enable multi-factor authentication"
                ],
                "auto_action": "RESET_SESSION",
                "target_pids": [p['pid'] for p in session_anomalies[:3]]
            })

        return threats

    def _detect_unauthorized_access(self, processes: List[Dict], security: Dict, network: Dict) -> List[Dict]:
        """
        Detect unauthorized access: Brute Force, Credential Stuffing, Backdoor, Path Traversal
        """
        threats = []
        connections = network.get('connections', [])

        # Brute Force indicator
        security_events = security.get('events', [])
        failed_logins = [
            e for e in security_events
            if 'failed' in (e.get('type') or '').lower() and 'login' in (e.get('type') or '').lower()
        ]

        if len(failed_logins) > 5:
            threats.append({
                "type": "BRUTE_FORCE_ATTACK",
                "severity": "HIGH",
                "confidence": 85,
                "description": f"Multiple failed login attempts detected ({len(failed_logins)}). Possible brute force attack.",
                "preventive_steps": [
                    "Lock the affected user account immediately",
                    "Enable account lockout policy",
                    "Force password reset for targeted accounts",
                    "Enable two-factor authentication",
                    "Block source IP addresses",
                    "Review login attempt logs",
                    "Use strong, unique passwords",
                    "Implement CAPTCHA on login forms"
                ],
                "auto_action": "LOCKDOWN",
                "target_pids": []
            })

        # Backdoor indicator
        rat_patterns = ['teamviewer', 'anydesk', 'ammyy', 'logmein', 'remote', 'vnc', 'rdp']
        suspicious_rats = [
            p for p in processes
            if any(r in (p.get('name') or '').lower() for r in rat_patterns)
            and any(bad in (p.get('exe_path') or '').lower() for bad in ['\\temp\\', '\\appdata\\'])
        ]

        if suspicious_rats:
            threats.append({
                "type": "BACKDOOR_DETECTED",
                "severity": "CRITICAL",
                "confidence": 90,
                "description": f"Remote access tool running from suspicious location: {suspicious_rats[0]['name']}. Possible backdoor.",
                "processes": [p['name'] for p in suspicious_rats],
                "preventive_steps": [
                    "IMMEDIATELY disconnect from internet",
                    "Terminate the remote access process",
                    "Block the application in firewall",
                    "Check for active remote sessions",
                    "Change all passwords",
                    "Review what the attacker may have accessed",
                    "Run full antivirus scan",
                    "Consider system reinstallation"
                ],
                "auto_action": "SUSPEND_PROCESS",
                "target_pids": [p['pid'] for p in suspicious_rats]
            })

        # Credential Stuffing
        auth_processes = [
            p for p in processes
            if any(a in (p.get('name') or '').lower() for a in ['login', 'auth', 'credential', 'password'])
        ]

        if len(auth_processes) > 5:
            threats.append({
                "type": "CREDENTIAL_STUFFING_INDICATOR",
                "severity": "MEDIUM",
                "confidence": 65,
                "description": "Multiple authentication-related processes active. Possible credential stuffing attack.",
                "preventive_steps": [
                    "Monitor account login activity",
                    "Enable two-factor authentication",
                    "Use unique passwords for each account",
                    "Check haveibeenpwned.com for breached credentials",
                    "Enable login notifications",
                    "Review recent account access",
                    "Implement rate limiting on login attempts",
                    "Use a password manager"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Path Traversal Detection
        for proc in processes:
            cmd_line = proc.get('command_line') or ''
            exe_path = (proc.get('exe_path') or '').lower()

            for pattern in self.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, cmd_line, re.IGNORECASE):
                    threats.append({
                        "type": "PATH_TRAVERSAL_DETECTED",
                        "severity": "HIGH",
                        "confidence": 80,
                        "description": f"Path traversal attack pattern detected in '{proc['name']}'. Attempt to access restricted directories.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "Terminate the suspicious process",
                            "Validate and sanitize file path inputs",
                            "Use allowlists for permitted directories",
                            "Implement chroot or sandboxing",
                            "Apply principle of least privilege",
                            "Use canonical path resolution",
                            "Enable file access logging",
                            "Review application file handling code"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })
                    break

        return threats

    def _detect_harm_disruption(self, system: Dict, processes: List[Dict]) -> List[Dict]:
        """
        Detect harm/disruption: Resource Exhaustion, Botnet, Logic Bomb, Time Bomb
        """
        threats = []

        # Detect suspicious Microsoft Store activity (repeated launches could indicate malware)
        store_processes = [
            p for p in processes
            if 'store' in (p.get('name') or '').lower() or
               'winstore' in (p.get('name') or '').lower() or
               'microsoft.store' in (p.get('name') or '').lower()
        ]

        # Multiple Store processes or high CPU usage by Store is suspicious
        if len(store_processes) > 2:
            threats.append({
                "type": "SUSPICIOUS_STORE_ACTIVITY",
                "severity": "MEDIUM",
                "confidence": 65,
                "description": f"Multiple Microsoft Store processes detected ({len(store_processes)}). Could indicate automatic app downloads or malware installing apps.",
                "processes": [p['name'] for p in store_processes],
                "preventive_steps": [
                    "Check Windows Store for pending downloads/updates",
                    "Review recently installed apps",
                    "Disable automatic app updates in Store settings",
                    "Check Task Scheduler for Store-related tasks",
                    "Run Windows Store Apps troubleshooter",
                    "Scan for malware that may be triggering Store",
                    "Check Group Policy for Store restrictions"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": [p['pid'] for p in store_processes]
            })

        # System resource exhaustion
        if system.get('cpu_percent', 0) > 95 and system.get('ram_percent', 0) > 95:
            threats.append({
                "type": "RESOURCE_EXHAUSTION_ATTACK",
                "severity": "HIGH",
                "confidence": 75,
                "description": "System resources critically exhausted (CPU >95%, RAM >95%). Possible DoS attack or wiper malware.",
                "preventive_steps": [
                    "Identify and terminate resource-hogging processes",
                    "Disconnect from network if under attack",
                    "Check for malware infection",
                    "Restart system in Safe Mode",
                    "Run antivirus scan",
                    "Check for wiper malware signatures",
                    "Backup important files immediately",
                    "Monitor for system file corruption"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Botnet indicator
        unknown_network_procs = [
            p for p in processes
            if not p.get('is_known', True) and p.get('risk_score', 0) > 60
        ]

        if unknown_network_procs:
            threats.append({
                "type": "BOTNET_INFECTION_INDICATOR",
                "severity": "CRITICAL",
                "confidence": 72,
                "description": f"Unknown process with suspicious behavior: {unknown_network_procs[0]['name']}. Possible botnet zombie.",
                "processes": [p['name'] for p in unknown_network_procs[:3]],
                "preventive_steps": [
                    "IMMEDIATELY disconnect from internet",
                    "Terminate the suspicious process",
                    "Block outbound connections in firewall",
                    "Check for DDoS attack participation",
                    "Run full malware scan",
                    "Review scheduled tasks for persistence",
                    "Check startup items",
                    "Consider system reinstallation"
                ],
                "auto_action": "SUSPEND_PROCESS",
                "target_pids": [p['pid'] for p in unknown_network_procs[:3]]
            })

        # Logic Bomb/Time Bomb Detection
        for proc in processes:
            name = (proc.get('name') or '').lower()
            cmd_line = (proc.get('command_line') or '').lower()

            logic_bomb_indicators = [
                'scheduled', 'trigger', 'time bomb', 'logic bomb',
                'if date', 'wait for', 'sleep', 'timeout',
                'delete all', 'format', 'wipe', 'destroy'
            ]

            if any(indicator in cmd_line for indicator in logic_bomb_indicators):
                if proc.get('risk_score', 0) > 50:
                    threats.append({
                        "type": "LOGIC_BOMB_DETECTED",
                        "severity": "CRITICAL",
                        "confidence": 70,
                        "description": f"Logic bomb/time bomb indicator detected in '{proc['name']}'. Time-triggered malicious code found.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "IMMEDIATELY terminate the process",
                            "Check scheduled tasks for malicious entries",
                            "Review startup items for suspicious programs",
                            "Scan for known logic bomb signatures",
                            "Check for time-based triggers in scripts",
                            "Monitor system for unusual scheduled activity",
                            "Backup important data immediately",
                            "Conduct thorough malware analysis"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })

            # Time Bomb specific detection
            time_bomb_indicators = [
                'datetime.now', 'time.sleep', 'scheduledtask',
                'cron', 'at ', 'schtasks', 'waitfor'
            ]
            if any(ind in cmd_line for ind in time_bomb_indicators):
                if proc.get('risk_score', 0) > 70:
                    threats.append({
                        "type": "TIME_BOMB_DETECTED",
                        "severity": "CRITICAL",
                        "confidence": 75,
                        "description": f"Time bomb trigger detected in '{proc['name']}'. Malware set to activate at specific time.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "IMMEDIATELY terminate the process",
                            "Disconnect from network",
                            "Check system time and scheduled tasks",
                            "Review all startup programs",
                            "Scan for time-based malware",
                            "Backup critical data",
                            "Monitor system clock for tampering",
                            "Analyze process for trigger conditions"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })

        return threats

    def _detect_infrastructure_exploitation(self, processes: List[Dict], security: Dict, network: Dict) -> List[Dict]:
        """
        Detect infrastructure exploitation: IoT Attacks, Supply Chain, Insider Threats, Firmware Integrity
        """
        threats = []
        connections = network.get('connections', [])

        # IoT attack indicator
        iot_ports = [1883, 8883, 5683, 5684]
        iot_connections = [c for c in connections if c.get('remote_port') in iot_ports]

        if len(iot_connections) > 3:
            threats.append({
                "type": "IOT_ATTACK_INDICATOR",
                "severity": "MEDIUM",
                "confidence": 60,
                "description": f"Connections to IoT device ports detected ({len(iot_connections)}). Possible IoT exploitation.",
                "preventive_steps": [
                    "Identify which IoT devices are being accessed",
                    "Verify access is authorized",
                    "Change default IoT device passwords",
                    "Update IoT device firmware",
                    "Segment IoT devices on separate network",
                    "Disable unnecessary IoT features",
                    "Monitor IoT device traffic",
                    "Enable IoT device encryption"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Supply chain attack
        startup_items = security.get('startup_items', [])
        recent_startup = [s for s in startup_items if 'recent' in (s.get('installed') or '').lower()]

        if recent_startup:
            threats.append({
                "type": "SUPPLY_CHAIN_ATTACK_INDICATOR",
                "severity": "HIGH",
                "confidence": 68,
                "description": "Recently installed software with startup privileges detected. Possible supply chain compromise.",
                "preventive_steps": [
                    "Review recently installed software",
                    "Verify software source and signatures",
                    "Check for software updates from vendor",
                    "Search for known vulnerabilities",
                    "Remove suspicious software",
                    "Monitor software behavior",
                    "Check vendor security advisories",
                    "Enable application whitelisting"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Insider threat
        high_priv_procs = [
            p for p in processes
            if (p.get('username') or '').lower() in ['system', 'administrator', 'admin']
        ]

        if len(high_priv_procs) > 10:
            threats.append({
                "type": "INSIDER_THREAT_INDICATOR",
                "severity": "MEDIUM",
                "confidence": 55,
                "description": f"Multiple high-privilege processes running ({len(high_priv_procs)}). Monitor for insider threat.",
                "preventive_steps": [
                    "Review which users have admin access",
                    "Audit privileged account activity",
                    "Enable detailed logging",
                    "Implement least-privilege access",
                    "Monitor file access patterns",
                    "Review access control policies",
                    "Enable data loss prevention",
                    "Conduct security awareness training"
                ],
                "auto_action": "ALERT_ONLY",
                "target_pids": []
            })

        # Firmware Integrity Check
        for proc in processes:
            name = (proc.get('name') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()

            firmware_indicators = ['firmware', 'bios', 'uefi', 'flash', 'rom']
            if any(ind in name or ind in exe_path for ind in firmware_indicators):
                if not proc.get('is_known', True) or proc.get('risk_score', 0) > 50:
                    threats.append({
                        "type": "FIRMWARE_INTEGRITY_WARNING",
                        "severity": "CRITICAL",
                        "confidence": 65,
                        "description": f"Process '{proc['name']}' accessing firmware/BIOS. Possible firmware tampering attempt.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "Verify if firmware update is legitimate",
                            "Check vendor website for official updates",
                            "Do NOT interrupt firmware update process",
                            "Enable Secure Boot in BIOS/UEFI",
                            "Verify firmware signature if possible",
                            "Backup current firmware if supported",
                            "Monitor for system instability after update",
                            "Report suspicious firmware activity"
                        ],
                        "auto_action": "ALERT_ONLY",
                        "target_pids": [proc['pid']]
                    })

        return threats

    def _detect_advanced_threats(self, processes: List[Dict], system: Dict, security: Dict) -> List[Dict]:
        """
        Detect advanced threats: Process Injection, DLL Side-Loading, Living-off-the-Land, Process Hollowing
        """
        threats = []

        # Process Injection Detection
        for proc in processes:
            name = (proc.get('name') or '').lower()
            risk_score = proc.get('risk_score', 0)

            injection_indicators = [
                'inject', 'hook', 'patch', 'modify', 'writeprocess',
                'createremotethread', 'ntcreatethreadex', 'queueuserapc'
            ]

            if any(ind in name for ind in injection_indicators) and risk_score > 60:
                threats.append({
                    "type": "PROCESS_INJECTION_DETECTED",
                    "severity": "CRITICAL",
                    "confidence": 80,
                    "description": f"Process injection indicator detected in '{proc['name']}'. Code injection into another process suspected.",
                    "processes": [proc['name']],
                    "preventive_steps": [
                        "IMMEDIATELY terminate the injecting process",
                        "Identify target process of injection",
                        "Check for malware persistence mechanisms",
                        "Enable Process Injection detection in EDR",
                        "Monitor for suspicious handle operations",
                        "Use Windows Defender Application Control",
                        "Review memory dumps for injected code",
                        "Scan for known injection techniques"
                    ],
                    "auto_action": "SUSPEND_PROCESS",
                    "target_pids": [proc['pid']]
                })

        # Process Hollowing Detection
        for proc in processes:
            name = (proc.get('name') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()
            risk_score = proc.get('risk_score', 0)

            # Check for legitimate process names running from suspicious locations
            legitimate_procs = ['svchost.exe', 'explorer.exe', 'notepad.exe', 'calc.exe']
            if any(legit in name for legit in legitimate_procs):
                if any(bad in exe_path for bad in ['\\temp\\', '\\appdata\\', '\\downloads\\']):
                    if risk_score > 60:
                        threats.append({
                            "type": "PROCESS_HOLLOWING_DETECTED",
                            "severity": "CRITICAL",
                            "confidence": 85,
                            "description": f"Process hollowing detected: '{proc['name']}' running from suspicious location. Legitimate process may be hollowed.",
                            "processes": [proc['name']],
                            "preventive_steps": [
                                "IMMEDIATELY terminate the hollowed process",
                                "Run antivirus scan",
                                "Check for malware persistence",
                                "Enable Windows Defender Application Control",
                                "Monitor for similar suspicious processes",
                                "Review process memory for anomalies",
                                "Check digital signatures",
                                "Consider system restore"
                            ],
                            "auto_action": "SUSPEND_PROCESS",
                            "target_pids": [proc['pid']]
                        })

        # DLL Side-Loading Detection
        for proc in processes:
            name = (proc.get('name') or '').lower()
            exe_path = (proc.get('exe_path') or '').lower()

            for trusted_app in self.DLL_SIDELOADING_INDICATORS['trusted_apps']:
                if trusted_app.lower() in name:
                    if any(bad in exe_path for bad in ['\\temp\\', '\\downloads\\', '\\appdata\\']):
                        threats.append({
                            "type": "DLL_SIDELOADING_DETECTED",
                            "severity": "HIGH",
                            "confidence": 75,
                            "description": f"Potential DLL side-loading: '{proc['name']}' running from suspicious location. Trusted app may be hijacked.",
                            "processes": [proc['name']],
                            "preventive_steps": [
                                "Terminate the suspicious process",
                                "Verify application installation source",
                                "Check for modified/tampered DLLs",
                                "Reinstall application from official source",
                                "Enable DLL loading security features",
                                "Use AppLocker to restrict DLL loading",
                                "Monitor for suspicious DLL files",
                                "Apply application security updates"
                            ],
                            "auto_action": "SUSPEND_PROCESS",
                            "target_pids": [proc['pid']]
                        })
                        break

        # Living-off-the-Land (LOLBin) Detection
        lolbins = ['powershell.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe',
                   'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'msbuild.exe']
        
        for proc in processes:
            name = (proc.get('name') or '').lower()
            cmd_line = (proc.get('command_line') or '').lower()
            risk_score = proc.get('risk_score', 0)

            if any(lolbin in name for lolbin in lolbins):
                # Check for suspicious LOLBin usage patterns
                lol_patterns = ['download', 'encode', 'decode', 'hidden', 'bypass',
                               'executionpolicy', 'encodedcommand', 'iex']
                if any(pattern in cmd_line for pattern in lol_patterns) and risk_score > 50:
                    threats.append({
                        "type": "LIVING_OFF_THE_LAND_DETECTED",
                        "severity": "HIGH",
                        "confidence": 75,
                        "description": f"Living-off-the-Land technique detected: '{proc['name']}' with suspicious parameters. Legitimate tool being misused.",
                        "processes": [proc['name']],
                        "preventive_steps": [
                            "Terminate the suspicious process",
                            "Review command-line arguments",
                            "Enable PowerShell logging",
                            "Monitor LOLBin usage",
                            "Implement application whitelisting",
                            "Review Windows event logs",
                            "Check for lateral movement",
                            "Update security policies"
                        ],
                        "auto_action": "SUSPEND_PROCESS",
                        "target_pids": [proc['pid']]
                    })

        return threats

    def _get_malware_steps(self, malware_type: str) -> List[str]:
        """Get preventive steps for specific malware type"""
        steps = {
            'ransomware': [
                "IMMEDIATELY disconnect from network",
                "Force shutdown to prevent further encryption",
                "Do NOT pay the ransom",
                "Boot from recovery media and backup files",
                "Run offline antivirus scan",
                "Restore from clean backup",
                "Identify ransomware variant",
                "Report to authorities"
            ],
            'trojan': [
                "Terminate the malicious process",
                "Disconnect from internet",
                "Change all passwords from clean device",
                "Check for backdoor access",
                "Run full antivirus scan",
                "Review installed programs",
                "Monitor network traffic",
                "Enable firewall rules"
            ],
            'spyware': [
                "Terminate spyware process",
                "Clear browser data and cookies",
                "Change compromised passwords",
                "Enable two-factor authentication",
                "Run anti-spyware scan",
                "Check browser extensions",
                "Monitor accounts for misuse",
                "Review app permissions"
            ],
            'rootkit': [
                "Boot from clean recovery media",
                "Run rootkit removal tools",
                "Check system file integrity",
                "Consider system reinstallation",
                "Update all drivers",
                "Enable secure boot",
                "Monitor for reinfection",
                "Use specialized rootkit detectors"
            ],
            'cryptominer': [
                "Terminate mining process",
                "Check browser extensions",
                "Review installed software",
                "Clear browser cache",
                "Block mining domains",
                "Monitor CPU usage",
                "Check scheduled tasks",
                "Update antivirus definitions"
            ],
            'worm': [
                "Disconnect from network immediately",
                "Terminate all worm process instances",
                "Run full antivirus scan",
                "Patch vulnerable services",
                "Check for infected files",
                "Enable firewall protection",
                "Scan removable drives",
                "Monitor network for reinfection"
            ],
            'adware': [
                "Remove suspicious browser extensions",
                "Reset browser settings to default",
                "Run anti-adware scan",
                "Check installed programs list",
                "Clear browser cache and data",
                "Enable pop-up blocker",
                "Review app permissions",
                "Install reputable ad-blocker"
            ]
        }
        return steps.get(malware_type, [
            "Terminate the malicious process",
            "Disconnect from network",
            "Run full antivirus scan",
            "Change passwords",
            "Monitor system behavior",
            "Update security software",
            "Review installed programs",
            "Enable enhanced protection"
        ])


# ============================================================================
# ANOMALY DETECTOR - ML-Based Statistical Anomaly Detection
# ============================================================================

class AnomalyDetector:
    """
    Machine learning-based anomaly detection using statistical baseline.
    Learns normal system behavior and flags deviations.
    """

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.cpu_history: deque = deque(maxlen=window_size)
        self.ram_history: deque = deque(maxlen=window_size)
        self.net_history: deque = deque(maxlen=window_size)
        self.process_count_history: deque = deque(maxlen=window_size)
        self.disk_history: deque = deque(maxlen=window_size)
        self.is_trained: bool = False
        self.MIN_SAMPLES: int = 20
        self.logger = logging.getLogger('SENTINEL.AnomalyDetector')

    def update_baseline(self, snapshot: Dict[str, Any]) -> None:
        """Update the baseline with new system snapshot."""
        try:
            system = snapshot.get("system", {})
            network = snapshot.get("network", {})
            processes = snapshot.get("processes", [])

            self.cpu_history.append(system.get("cpu_percent", 0))
            self.ram_history.append(system.get("ram_percent", 0))
            self.net_history.append(network.get("bytes_sent", 0))
            self.disk_history.append(system.get("disk_percent", 0))
            self.process_count_history.append(len(processes))

            if len(self.cpu_history) >= self.MIN_SAMPLES:
                self.is_trained = True
        except Exception as e:
            self.logger.error(f"Error updating baseline: {e}")

    def calculate_anomaly_score(self, snapshot: Dict[str, Any]) -> Tuple[float, str]:
        """Calculate anomaly score for current snapshot."""
        if not self.is_trained:
            return 0.0, "Still learning baseline..."

        try:
            system = snapshot.get("system", {})
            network = snapshot.get("network", {})
            processes = snapshot.get("processes", [])

            scores = []
            reasons = []

            # CPU anomaly
            if self.cpu_history:
                avg_cpu = sum(self.cpu_history) / len(self.cpu_history)
                std_cpu = self._std(self.cpu_history)
                current_cpu = system.get("cpu_percent", 0)
                cpu_z = abs(current_cpu - avg_cpu) / (std_cpu + 1)
                cpu_score = min(cpu_z / 3.0, 1.0)
                scores.append(cpu_score)
                if cpu_score > 0.7:
                    reasons.append(f"CPU unusually high ({current_cpu:.1f}% vs normal {avg_cpu:.1f}%)")

            # RAM anomaly
            if self.ram_history:
                avg_ram = sum(self.ram_history) / len(self.ram_history)
                std_ram = self._std(self.ram_history)
                current_ram = system.get("ram_percent", 0)
                ram_z = abs(current_ram - avg_ram) / (std_ram + 1)
                ram_score = min(ram_z / 3.0, 1.0)
                scores.append(ram_score)
                if ram_score > 0.7:
                    reasons.append(f"RAM unusually high ({current_ram:.1f}% vs normal {avg_ram:.1f}%)")

            # Network anomaly
            if self.net_history:
                avg_net = sum(self.net_history) / len(self.net_history)
                current_net = network.get("bytes_sent", 0)
                if avg_net > 0:
                    net_diff = abs(current_net - avg_net) / avg_net
                    net_score = min(net_diff, 1.0)
                    scores.append(net_score)
                    if net_score > 0.7:
                        reasons.append(f"Network traffic anomaly ({current_net/1000:.0f}KB vs normal {avg_net/1000:.0f}KB)")

            # Disk anomaly
            if self.disk_history:
                avg_disk = sum(self.disk_history) / len(self.disk_history)
                current_disk = system.get("disk_percent", 0)
                disk_diff = abs(current_disk - avg_disk) / (avg_disk + 1)
                disk_score = min(disk_diff, 1.0)
                scores.append(disk_score)
                if disk_score > 0.7:
                    reasons.append(f"Disk usage anomaly ({current_disk:.1f}% vs normal {avg_disk:.1f}%)")

            # Process count anomaly
            if self.process_count_history:
                avg_procs = sum(self.process_count_history) / len(self.process_count_history)
                current_procs = len(processes)
                proc_diff = abs(current_procs - avg_procs) / (avg_procs + 1)
                proc_score = min(proc_diff, 1.0)
                scores.append(proc_score)
                if proc_score > 0.5:
                    reasons.append(f"Unusual number of processes ({current_procs} vs normal {avg_procs:.0f})")

            if not scores:
                return 0.0, "Insufficient data"

            final_score = sum(scores) / len(scores)
            reason_text = "; ".join(reasons) if reasons else "Behavior within normal range"

            return round(final_score, 3), reason_text

        except Exception as e:
            self.logger.error(f"Error calculating anomaly score: {e}")
            return 0.0, "Error calculating anomaly score"

    def _std(self, data: deque) -> float:
        """Calculate standard deviation"""
        if len(data) < 2:
            return 1
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        return variance ** 0.5


# ============================================================================
# THREAT CLASSIFIER - Threat Response and Classification
# ============================================================================

class ThreatClassifier:
    """
    Classifies detected threats and assigns appropriate responses.
    Contains threat metadata including icons, colors, and user messages.
    """

    THREAT_RESPONSES: Dict[str, Dict[str, str]] = {
        # ==================== MALWARE ====================
        "RANSOMWARE_DETECTED": {
            "icon": "🔒", "color": "#ef4444",
            "immediate_action": "Process terminated. System isolation recommended.",
            "user_message": "CRITICAL: Ransomware detected! Your files are at immediate risk of encryption."
        },
        "RANSOMWARE_ACTIVITY": {
            "icon": "🔒", "color": "#ef4444",
            "immediate_action": "Emergency shutdown recommended. File encryption in progress.",
            "user_message": "CRITICAL: Active ransomware encryption detected! Shut down immediately!"
        },
        "TROJAN_DETECTED": {
            "icon": "🐴", "color": "#ef4444",
            "immediate_action": "Trojan process suspended. Checking for backdoor access.",
            "user_message": "Trojan horse detected! This malware creates hidden access for attackers."
        },
        "SPYWARE_DETECTED": {
            "icon": "👁️", "color": "#f97316",
            "immediate_action": "Spyware terminated. Password change recommended.",
            "user_message": "Spyware detected! Your activities and data may have been monitored."
        },
        "ROOTKIT_DETECTED": {
            "icon": "🔧", "color": "#ef4444",
            "immediate_action": "Rootkit detected. System recovery may be required.",
            "user_message": "CRITICAL: Rootkit detected! This malware hides deep in your system."
        },
        "CRYPTOMINER_DETECTED": {
            "icon": "⛏️", "color": "#f97316",
            "immediate_action": "Cryptominer suspended to stop resource abuse.",
            "user_message": "Cryptominer detected! Your PC was being used to mine cryptocurrency."
        },
        "VIRUS_WORM_DETECTED": {
            "icon": "🦠", "color": "#f97316",
            "immediate_action": "Virus/Worm process terminated. Network isolation recommended.",
            "user_message": "Virus or Worm detected! This malware can spread to other systems."
        },
        "ADWARE_DETECTED": {
            "icon": "📢", "color": "#eab308",
            "immediate_action": "Adware detected. Browser cleanup recommended.",
            "user_message": "Adware detected! Unwanted advertisements and tracking found."
        },

        # ==================== SOCIAL ENGINEERING ====================
        "BAITING_ATTACK_INDICATOR": {
            "icon": "🎣", "color": "#f97316",
            "immediate_action": "Unknown USB device flagged. Do not use.",
            "user_message": "Potential baiting attack! Unknown USB device may contain malware."
        },
        "INFOSTEALER_INDICATOR": {
            "icon": "🦹", "color": "#ef4444",
            "immediate_action": "Screen capture blocked. Change passwords immediately.",
            "user_message": "CRITICAL: Infostealer activity! Your passwords and data may be stolen."
        },
        "INFOSTEALER_DETECTED": {
            "icon": "🦹", "color": "#ef4444",
            "immediate_action": "Password stealer terminated. Change all passwords.",
            "user_message": "CRITICAL: Infostealer malware! Your saved passwords are being stolen."
        },
        "PHISHING_INDICATOR": {
            "icon": "📧", "color": "#eab308",
            "immediate_action": "Phishing activity detected. Verify website authenticity.",
            "user_message": "Phishing indicator detected! You may be on a fake website."
        },
        "TECH_SUPPORT_SCAM_DETECTED": {
            "icon": "📞", "color": "#f97316",
            "immediate_action": "Tech support scam page detected. Do not call any numbers.",
            "user_message": "Tech Support Scam detected! This is a fake alert - do not call any numbers."
        },

        # ==================== NETWORK ATTACKS ====================
        "DDOS_ATTACK_INDICATOR": {
            "icon": "🌊", "color": "#f97316",
            "immediate_action": "Abnormal traffic detected. Consider disconnecting.",
            "user_message": "Possible DDoS attack! Your system may be overwhelmed or participating in attack."
        },
        "MITM_ATTACK_INDICATOR": {
            "icon": "👤", "color": "#f97316",
            "immediate_action": "Network interception suspected. Use VPN.",
            "user_message": "Man-in-the-Middle attack suspected! Your communications may be intercepted."
        },
        "DNS_SPOOFING_INDICATOR": {
            "icon": "🎭", "color": "#eab308",
            "immediate_action": "DNS manipulation detected. Change DNS server.",
            "user_message": "DNS spoofing detected! You may be redirected to fake websites."
        },
        "SSRF_ATTACK_INDICATOR": {
            "icon": "🔗", "color": "#f97316",
            "immediate_action": "SSRF attack detected. Blocking internal IP access.",
            "user_message": "SSRF attack detected! Application attempting to access internal resources."
        },

        # ==================== CODE INJECTION ====================
        "SQL_INJECTION_EXPLOITATION": {
            "icon": "💉", "color": "#ef4444",
            "immediate_action": "Database exploitation detected. Isolate system.",
            "user_message": "CRITICAL: SQL injection attack! Your database is being compromised."
        },
        "XSS_ATTACK_INDICATOR": {
            "icon": "📜", "color": "#f97316",
            "immediate_action": "Script injection detected. Clear browser data.",
            "user_message": "Cross-Site Scripting attack detected! Your browser session may be compromised."
        },
        "COMMAND_INJECTION_DETECTED": {
            "icon": "💻", "color": "#ef4444",
            "immediate_action": "Command injection detected. Terminating process.",
            "user_message": "CRITICAL: Command injection attack! Malicious commands being executed."
        },
        "LDAP_INJECTION_DETECTED": {
            "icon": "📇", "color": "#f97316",
            "immediate_action": "LDAP injection detected. Terminating process.",
            "user_message": "LDAP injection attack detected! Directory service being exploited."
        },
        "XXE_INJECTION_DETECTED": {
            "icon": "📄", "color": "#f97316",
            "immediate_action": "XXE injection detected. Blocking external entities.",
            "user_message": "XXE injection attack detected! XML parser being exploited."
        },
        "ZERO_DAY_EXPLOIT_INDICATOR": {
            "icon": "👾", "color": "#ef4444",
            "immediate_action": "Unknown exploit detected. Maximum alert.",
            "user_message": "CRITICAL: Possible zero-day exploit! Unknown attack method detected."
        },

        # ==================== FILELESS & ADVANCED ATTACKS ====================
        "FILELESS_MALWARE_DETECTED": {
            "icon": "👻", "color": "#ef4444",
            "immediate_action": "Fileless malware detected. Terminating PowerShell process.",
            "user_message": "CRITICAL: Fileless malware detected! Attack running in memory only."
        },
        "FILELESS_MALWARE_WMI_ABUSE": {
            "icon": "🔮", "color": "#f97316",
            "immediate_action": "WMI abuse detected. Checking for persistence.",
            "user_message": "Fileless attack via WMI detected! Malware using Windows Management Instrumentation."
        },
        "FILELESS_MALWARE_SCRIPT_HOST": {
            "icon": "📝", "color": "#f97316",
            "immediate_action": "Suspicious script host activity detected.",
            "user_message": "Fileless script execution detected! Malware using Windows Script Host."
        },
        "PROCESS_INJECTION_DETECTED": {
            "icon": "💉", "color": "#ef4444",
            "immediate_action": "Process injection detected. Terminating malicious process.",
            "user_message": "CRITICAL: Process injection detected! Code being injected into legitimate processes."
        },
        "PROCESS_HOLLOWING_DETECTED": {
            "icon": "🕳️", "color": "#ef4444",
            "immediate_action": "Process hollowing detected. Terminating hollowed process.",
            "user_message": "CRITICAL: Process hollowing detected! Legitimate process replaced with malicious code."
        },
        "DLL_SIDELOADING_DETECTED": {
            "icon": "🔧", "color": "#f97316",
            "immediate_action": "DLL side-loading detected. Application may be compromised.",
            "user_message": "DLL Side-Loading detected! Legitimate application being abused to load malicious DLL."
        },
        "LIVING_OFF_THE_LAND_DETECTED": {
            "icon": "🎭", "color": "#f97316",
            "immediate_action": "LOLBin technique detected. Terminating process.",
            "user_message": "Living-off-the-Land attack detected! Legitimate tool being misused for malicious purposes."
        },

        # ==================== WEB-BASED THREATS ====================
        "WEB_CRYPTOJACKING_DETECTED": {
            "icon": "🪙", "color": "#f97316",
            "immediate_action": "Cryptojacking script detected. Close browser tab.",
            "user_message": "Web-based Cryptojacking detected! Website mining cryptocurrency using your CPU."
        },
        "DRIVE_BY_DOWNLOAD_DETECTED": {
            "icon": "📥", "color": "#f97316",
            "immediate_action": "Drive-by download detected. Do not open downloaded files.",
            "user_message": "Drive-by Download detected! Malware downloaded without your consent."
        },
        "CSRF_ATTACK_INDICATOR": {
            "icon": "🔄", "color": "#eab308",
            "immediate_action": "CSRF attack indicator. Clear session data.",
            "user_message": "CSRF attack indicator! Unauthorized requests may have been submitted."
        },
        "TYPOSQUATTING_DETECTED": {
            "icon": "🔤", "color": "#eab308",
            "immediate_action": "Typosquatting domain detected. Verify URL.",
            "user_message": "Typosquatting detected! You may be on a fake website with similar name."
        },
        "HOMOGRAPH_ATTACK_DETECTED": {
            "icon": "🔣", "color": "#f97316",
            "immediate_action": "Homograph attack detected. Do not enter credentials.",
            "user_message": "Homograph attack detected! Fake domain using Unicode lookalike characters."
        },
        "WATERING_HOLE_ATTACK_DETECTED": {
            "icon": "💧", "color": "#f97316",
            "immediate_action": "Watering hole attack detected. Close browser.",
            "user_message": "Watering Hole attack detected! Compromised website trying to infect your system."
        },
        "QR_CODE_PHISHING_DETECTED": {
            "icon": "📱", "color": "#eab308",
            "immediate_action": "QR code phishing detected. Do not scan.",
            "user_message": "QR Code Phishing (Quishing) detected! Malicious QR code trying to redirect you."
        },
        "FORMJACKING_DETECTED": {
            "icon": "🛒", "color": "#ef4444",
            "immediate_action": "Formjacking detected. Do not enter payment info.",
            "user_message": "CRITICAL: Formjacking detected! Your payment data is being stolen."
        },
        "RAAS_NETWORK_INDICATOR": {
            "icon": "🕸️", "color": "#ef4444",
            "immediate_action": "Ransomware-as-a-Service network detected. Blocking connection.",
            "user_message": "CRITICAL: RaaS network indicator! Connection to known ransomware infrastructure."
        },
        "DOUBLE_EXTORTION_RANSOMWARE": {
            "icon": "🔒", "color": "#ef4444",
            "immediate_action": "Double extortion ransomware! Emergency shutdown NOW!",
            "user_message": "CRITICAL: Double extortion ransomware! Your data is being uploaded before encryption!"
        },
        "WIPER_MALWARE_DETECTED": {
            "icon": "💀", "color": "#ef4444",
            "immediate_action": "Wiper malware! Destructive attack - data will be permanently destroyed!",
            "user_message": "CRITICAL: Wiper malware detected! This destroys data permanently - no recovery possible!"
        },
        "DEAD_MANS_SWITCH_DETECTED": {
            "icon": "⏰", "color": "#ef4444",
            "immediate_action": "Dead man's switch detected! Do NOT disconnect network abruptly!",
            "user_message": "CRITICAL: Dead man's switch detected! Malware may activate if beacon stops!"
        },

        # ==================== DATA THEFT ====================
        "PACKET_SNIFFING_DETECTED": {
            "icon": "📦", "color": "#f97316",
            "immediate_action": "Network eavesdropping detected. Use encryption.",
            "user_message": "Packet sniffing detected! Your network traffic is being captured."
        },
        "DATA_EXFILTRATION_INDICATOR": {
            "icon": "📤", "color": "#ef4444",
            "immediate_action": "Data theft in progress. Disconnect immediately.",
            "user_message": "CRITICAL: Data exfiltration! Your files are being sent to attackers."
        },
        "SESSION_HIJACKING_INDICATOR": {
            "icon": "🍪", "color": "#f97316",
            "immediate_action": "Session hijacking indicator. Clear cookies.",
            "user_message": "Session Hijacking indicator! Your session cookies may be stolen."
        },

        # ==================== UNAUTHORIZED ACCESS ====================
        "BRUTE_FORCE_ATTACK": {
            "icon": "🔨", "color": "#f97316",
            "immediate_action": "Multiple login failures. Account lockdown initiated.",
            "user_message": "Brute force attack detected! Someone is trying to guess your password."
        },
        "BACKDOOR_DETECTED": {
            "icon": "🚪", "color": "#ef4444",
            "immediate_action": "Remote backdoor terminated. Disconnect from internet.",
            "user_message": "CRITICAL: Backdoor detected! Attackers have remote access to your system."
        },
        "CREDENTIAL_STUFFING_INDICATOR": {
            "icon": "🔑", "color": "#eab308",
            "immediate_action": "Credential attack suspected. Enable 2FA.",
            "user_message": "Credential stuffing attack! Attackers are using stolen passwords."
        },
        "PATH_TRAVERSAL_DETECTED": {
            "icon": "📁", "color": "#f97316",
            "immediate_action": "Path traversal attack detected. Blocking access.",
            "user_message": "Path Traversal attack detected! Attempt to access restricted directories."
        },

        # ==================== HARM & DISRUPTION ====================
        "RESOURCE_EXHAUSTION_ATTACK": {
            "icon": "🔋", "color": "#f97316",
            "immediate_action": "System resources critical. Terminating processes.",
            "user_message": "System under attack! Resources being exhausted to crash your system."
        },
        "BOTNET_INFECTION_INDICATOR": {
            "icon": "🤖", "color": "#ef4444",
            "immediate_action": "Botnet malware detected. Isolate system.",
            "user_message": "CRITICAL: Botnet infection! Your PC is being controlled by attackers."
        },
        "LOGIC_BOMB_DETECTED": {
            "icon": "💣", "color": "#ef4444",
            "immediate_action": "Logic bomb detected. Time-triggered malware found.",
            "user_message": "CRITICAL: Logic Bomb detected! Malware set to trigger at specific time."
        },
        "TIME_BOMB_DETECTED": {
            "icon": "⏰", "color": "#ef4444",
            "immediate_action": "Time bomb detected. Terminating trigger process.",
            "user_message": "CRITICAL: Time Bomb detected! Malware waiting for specific time to activate."
        },

        # ==================== INFRASTRUCTURE ====================
        "IOT_ATTACK_INDICATOR": {
            "icon": "📱", "color": "#eab308",
            "immediate_action": "IoT device access detected. Verify authorization.",
            "user_message": "IoT attack indicator! Your smart devices may be targeted."
        },
        "SUPPLY_CHAIN_ATTACK_INDICATOR": {
            "icon": "🔗", "color": "#f97316",
            "immediate_action": "Compromised software detected. Review installations.",
            "user_message": "Supply chain attack indicator! Legitimate software may be compromised."
        },
        "INSIDER_THREAT_INDICATOR": {
            "icon": "👤", "color": "#eab308",
            "immediate_action": "Unusual privileged activity. Audit recommended.",
            "user_message": "Insider threat indicator! Unusual admin activity detected."
        },
        "FIRMWARE_INTEGRITY_WARNING": {
            "icon": "🔌", "color": "#ef4444",
            "immediate_action": "Firmware access detected. Verify legitimacy.",
            "user_message": "CRITICAL: Firmware integrity warning! BIOS/UEFI may be tampered."
        },

        # ==================== ML ANOMALY ====================
        "ANOMALY": {
            "icon": "🔍", "color": "#eab308",
            "immediate_action": "Anomalous behavior logged and monitored.",
            "user_message": "Your PC is behaving differently than usual. This could indicate an unknown threat."
        },

        # ==================== ERRORS ====================
        "DETECTION_ERROR": {
            "icon": "⚠️", "color": "#eab308",
            "immediate_action": "Detection engine error. Service restart recommended.",
            "user_message": "Detection engine encountered an error. Please restart SENTINEL."
        }
    }

    def classify(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a threat and add response metadata."""
        threat_type = threat.get("type", "ANOMALY")
        response_info = self.THREAT_RESPONSES.get(threat_type, self.THREAT_RESPONSES["ANOMALY"])

        return {
            **threat,
            **response_info,
            "id": f"threat_{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{random.randint(1000, 9999)}",
            "detected_at": datetime.datetime.utcnow().isoformat(),
            "status": "ACTIVE"
        }


# ============================================================================
# SENTINEL DETECTOR - Main Detection Orchestrator
# ============================================================================

class SentinelDetector:
    """
    Main detection orchestrator that coordinates all detection engines.
    Provides unified interface for threat detection and auto-response execution.
    """

    def __init__(self, quarantine_dir: str = None, log_dir: str = None):
        self.rule_engine = RuleEngine()
        self.anomaly_detector = AnomalyDetector()
        self.classifier = ThreatClassifier()
        self.auto_response = AutoResponseEngine(quarantine_dir, log_dir)
        self.threat_history: List[Dict] = []
        self.logger = logging.getLogger('SENTINEL.Detector')
        self.logger.info("SENTINEL Threat Detection Engine initialized with Auto-Response")

    def analyze(self, snapshot: Dict[str, Any], auto_respond: bool = True) -> Dict[str, Any]:
        """
        Main analysis method - orchestrates all detection modules and executes auto-responses.

        Args:
            snapshot: Complete system snapshot
            auto_respond: Whether to automatically execute responses (default: True)

        Returns:
            Detection results dictionary
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

            # Classify all threats
            classified = [self.classifier.classify(t) for t in rule_threats]
            self.threat_history.extend(classified)

            # Execute auto-responses for detected threats
            auto_response_results = []
            if auto_respond and classified:
                for threat in classified:
                    action_str = threat.get('auto_action', 'ALERT_ONLY')
                    try:
                        action = AutoAction(action_str)
                        result = self.auto_response.execute(action, threat)
                        auto_response_results.append(result.to_dict())
                        self.logger.info(f"Auto-response executed for {threat['type']}: {result.success}")
                    except ValueError:
                        self.logger.warning(f"Unknown auto_action: {action_str} for {threat['type']}")

            # Log detection results
            if classified:
                self.logger.info(f"Detected {len(classified)} threats: {[t['type'] for t in classified]}")

            return {
                "threats": classified,
                "anomaly_score": anomaly_score,
                "anomaly_reason": anomaly_reason,
                "is_baseline_ready": self.anomaly_detector.is_trained,
                "baseline_progress": min(len(self.anomaly_detector.cpu_history), 20) * 5,
                "total_threats_detected": len(self.threat_history),
                "system_status": self._get_system_status(classified, anomaly_score),
                "auto_response_results": auto_response_results,
                "detection_timestamp": datetime.datetime.utcnow().isoformat()
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
                "detection_timestamp": datetime.datetime.utcnow().isoformat()
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

    def get_auto_response_history(self, limit: int = 50) -> List[Dict]:
        """Get recent auto-response execution history."""
        return self.auto_response.get_action_history(limit)

    def get_quarantined_files(self) -> List[Dict]:
        """Get list of quarantined files."""
        return self.auto_response.get_quarantined_files()

    def reset_baseline(self) -> None:
        """Reset the ML baseline for retraining"""
        self.anomaly_detector = AnomalyDetector()
        self.logger.info("ML baseline reset for retraining")

    def get_quarantine_status(self) -> Dict[str, Any]:
        """Get quarantine status and files information"""
        quarantined_files = self.auto_response.get_quarantined_files()
        return {
            "quarantine_active": True,
            "total_files": len(quarantined_files),
            "files": quarantined_files,
            "quarantine_directory": self.auto_response.quarantine_dir
        }

    def rollback_action(self, action_index: int) -> Dict[str, Any]:
        """Rollback a specific auto-response action by index"""
        try:
            result = self.auto_response.rollback_action(action_index)
            return {
                "success": result.success,
                "action": result.action,
                "message": result.message,
                "rollback_instructions": result.rollback_instructions
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  🛡️  SENTINEL - Comprehensive Threat Detection Engine v2.0")
    print("  AI-Powered Endpoint Security System with Auto-Response")
    print("=" * 70)
    print()
    print("Detecting 60+ threat types across 12 categories:")
    print()
    print("  1. Malware (Ransomware, Trojan, Spyware, Rootkit, etc.)")
    print("  2. Social Engineering (Phishing, Baiting, Tech Support Scam)")
    print("  3. Network Attacks (DDoS, MITM, DNS Spoofing, SSRF)")
    print("  4. Code Injection (SQLi, XSS, Command, LDAP, XXE)")
    print("  5. Fileless Attacks (PowerShell, WMI, Script Host)")
    print("  6. Web Threats (Cryptojacking, Drive-by, CSRF, Typosquatting)")
    print("  7. Data Theft (Infostealer, Packet Sniffing, Exfiltration)")
    print("  8. Unauthorized Access (Brute Force, Backdoor, Path Traversal)")
    print("  9. Harm & Disruption (Resource Exhaustion, Botnet, Logic Bomb)")
    print(" 10. Infrastructure (IoT, Supply Chain, Insider, Firmware)")
    print(" 11. Advanced Threats (Process Injection, DLL Side-Loading)")
    print(" 12. Zero-Day & ML Anomaly Detection")
    print()
    print("=" * 70)
    print("  Auto-Response Capabilities:")
    print("  - SUSPEND_PROCESS: Terminate malicious processes")
    print("  - BLOCK_IP: Add Windows Firewall rules")
    print("  - ISOLATE_AND_ALERT: Disable network adapters")
    print("  - LOCKDOWN: Lock workstation, disable guest, enable security")
    print("  - EMERGENCY_SHUTDOWN: Safe system shutdown")
    print("  - QUARANTINE_FILE: Move suspicious files to quarantine")
    print("  - RESET_SESSION: Clear browser cookies/sessions")
    print("  - CLEAR_CACHE: Clear temporary files")
    print("  - DISABLE_SERVICE: Stop Windows services")
    print("  - ALERT_ONLY: Log and notify")
    print("=" * 70)
    print("  Detection Engine Ready - Waiting for system snapshots...")
    print("=" * 70)

    # Initialize detector
    detector = SentinelDetector()

    # Print threat response catalog
    print("\n📋 Threat Response Catalog:")
    print("-" * 70)
    classifier = ThreatClassifier()
    for threat_type, response in sorted(classifier.THREAT_RESPONSES.items()):
        print(f"  {response['icon']} {threat_type}: {response['user_message'][:60]}...")
