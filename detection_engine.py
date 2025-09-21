from scapy.all import *
import datetime
from collections import defaultdict, deque
import json

class ThreatDetectionEngine:
    def __init__(self):
        # Track connection attempts per IP
        self.connection_attempts = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)  # IP -> set of ports accessed
        self.packet_frequency = defaultdict(deque)  # IP -> timestamp queue
        
        # Detection thresholds
        self.BRUTE_FORCE_THRESHOLD = 10  # connections per minute
        self.PORT_SCAN_THRESHOLD = 5     # different ports accessed
        self.PACKET_RATE_THRESHOLD = 50  # packets per minute
        
        # Suspicious ports (commonly targeted)
        self.SUSPICIOUS_PORTS = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S",
            1433: "SQL Server", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
        }
        
        # Known malicious IPs (example list - you can expand this)
	
        self.BLACKLISTED_IPS = {
            "192.168.1.666",  # Example malicious IP
            "10.0.0.666",     # Another example
        }
        
        self.alerts = []
    
    def analyze_packet(self, packet):
        """Main detection analysis for each packet"""
        current_time = datetime.datetime.now()
        alerts = []
        
        # Get IP information
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_version = "IPv4"
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            ip_version = "IPv6"
        else:
            return alerts
        
        # Detection Rule 1: Blacklisted IP Check
        if src_ip in self.BLACKLISTED_IPS:
            alert = self.create_alert("BLACKLISTED_IP", src_ip, dst_ip, 
                                    f"Traffic from blacklisted IP: {src_ip}")
            alerts.append(alert)
        
        # Detection Rule 2: Suspicious Port Analysis
        if TCP in packet:
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
            
            if dst_port in self.SUSPICIOUS_PORTS:
                alert = self.create_alert("SUSPICIOUS_PORT", src_ip, dst_ip,
                                        f"Access to {self.SUSPICIOUS_PORTS[dst_port]} port {dst_port}")
                alerts.append(alert)
            
            # Track port scanning behavior
            self.port_scan_tracker[src_ip].add(dst_port)
            if len(self.port_scan_tracker[src_ip]) >= self.PORT_SCAN_THRESHOLD:
                alert = self.create_alert("PORT_SCAN", src_ip, dst_ip,
                                        f"Potential port scan detected from {src_ip}")
                alerts.append(alert)
        
        # Detection Rule 3: High Frequency Attack Detection
        self.packet_frequency[src_ip].append(current_time)
        
        # Keep only packets from last minute
        minute_ago = current_time - datetime.timedelta(minutes=1)
        while (self.packet_frequency[src_ip] and 
               self.packet_frequency[src_ip][0] < minute_ago):
            self.packet_frequency[src_ip].popleft()
        
        # Check if packet rate exceeds threshold
        if len(self.packet_frequency[src_ip]) >= self.PACKET_RATE_THRESHOLD:
            alert = self.create_alert("HIGH_FREQUENCY", src_ip, dst_ip,
                                    f"High packet rate from {src_ip}: {len(self.packet_frequency[src_ip])} packets/min")
            alerts.append(alert)
        
        return alerts
    
    def create_alert(self, alert_type, src_ip, dst_ip, description):
        """Create standardized alert"""
        alert = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": alert_type,
            "severity": self.get_severity(alert_type),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "description": description
        }
        self.alerts.append(alert)
        return alert
    
    def get_severity(self, alert_type):
        """Assign severity levels"""
        severity_map = {
            "BLACKLISTED_IP": "HIGH",
            "PORT_SCAN": "MEDIUM",
            "SUSPICIOUS_PORT": "LOW",
            "HIGH_FREQUENCY": "MEDIUM"
        }
        return severity_map.get(alert_type, "LOW")
    
    def get_statistics(self):
        """Get detection statistics"""
        alert_counts = defaultdict(int)
        for alert in self.alerts:
            alert_counts[alert["type"]] += 1
        
        return {
            "total_alerts": len(self.alerts),
            "alert_breakdown": dict(alert_counts),
            "unique_threat_sources": len(set(alert["source_ip"] for alert in self.alerts))
        }
