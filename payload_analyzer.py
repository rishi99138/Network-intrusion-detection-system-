import re
from scapy.all import *
from collections import defaultdict
import datetime

class PayloadAnalyzer:
    def __init__(self):
        # Common attack signatures using regex patterns
        self.attack_signatures = {
            'SQL_INJECTION': [
                r'(\bUNION\b.*\bSELECT\b)',
                r'(\bOR\b.*1\s*=\s*1)',
                r'(\bDROP\b.*\bTABLE\b)',
                r'(\bINSERT\b.*\bINTO\b)',
                r'(\bDELETE\b.*\bFROM\b)'
            ],
            'XSS_ATTACK': [
                r'<script[^>]*>.*?</script>',
                r'javascript:.*',
                r'onload\s*=',
                r'onerror\s*=',
                r'<img[^>]*src\s*=\s*["\']javascript:'
            ],
            'COMMAND_INJECTION': [
                r';\s*(ls|dir|cat|type|whoami|id)\b',
                r'\|\s*(nc|netcat|bash|sh|cmd)\b',
                r'`.*`',
                r'\$\(.*\)',
                r'&&\s*(rm|del|format)\b'
            ],
            'SUSPICIOUS_USER_AGENTS': [
                r'sqlmap',
                r'nikto',
                r'nmap',
                r'masscan',
                r'metasploit',
                r'burpsuite'
            ],
            'MALWARE_SIGNATURES': [
                r'eval\s*\(\s*base64_decode',
                r'shell_exec\s*\(',
                r'system\s*\(',
                r'exec\s*\(',
                r'passthru\s*\('
            ]
        }
        
        # Track payload analysis statistics
        self.payload_stats = defaultdict(int)
    
    def analyze_payload(self, packet):
        """Analyze packet payload for malicious patterns"""
        alerts = []
        
        try:
            if Raw in packet:
                payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
                
                # Skip empty or very short payloads
                if len(payload) < 10:
                    return alerts
                
                # Get source information
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                elif IPv6 in packet:
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst
                else:
                    return alerts
                
                # Check against all attack signatures
                for attack_type, patterns in self.attack_signatures.items():
                    for pattern in patterns:
                        if re.search(pattern, payload, re.IGNORECASE):
                            alert = {
                                "timestamp": datetime.datetime.now().isoformat(),
                                "type": f"PAYLOAD_{attack_type}",
                                "severity": self.get_payload_severity(attack_type),
                                "source_ip": src_ip,
                                "destination_ip": dst_ip,
                                "description": f"Malicious payload detected: {attack_type}",
                                "matched_pattern": pattern,
                                "payload_sample": payload[:100] + "..." if len(payload) > 100 else payload
                            }
                            alerts.append(alert)
                            self.payload_stats[attack_type] += 1
                            break  # Only report first match per category
                
        except Exception as e:
            # Silently handle decode errors for binary payloads
            pass
        
        return alerts
    
    def get_payload_severity(self, attack_type):
        """Assign severity based on attack type"""
        severity_map = {
            'SQL_INJECTION': 'HIGH',
            'XSS_ATTACK': 'MEDIUM',
            'COMMAND_INJECTION': 'HIGH',
            'SUSPICIOUS_USER_AGENTS': 'LOW',
            'MALWARE_SIGNATURES': 'HIGH'
        }
        return severity_map.get(attack_type, 'MEDIUM')
    
    def get_payload_statistics(self):
        """Get payload analysis statistics"""
        return dict(self.payload_stats)
