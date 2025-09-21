import random
import datetime
import json
from datetime import datetime, timedelta

class NIDSDemoData:
    def __init__(self):
        self.demo_ips = [
            "192.168.1.45", "10.0.0.23", "172.16.1.87", "203.0.113.45",
            "198.51.100.32", "169.254.1.15", "192.168.0.100", "10.1.1.50",
            "172.16.0.25", "10.0.1.150", "192.168.2.75", "203.0.113.90"
        ]
        
        self.threat_types = [
            "PORT_SCAN", "SUSPICIOUS_PORT", "SQL_INJECTION", "XSS_ATTACK",
            "COMMAND_INJECTION", "HIGH_FREQUENCY", "MALWARE_SIGNATURES", "BLACKLISTED_IP"
        ]
        
        self.locations = [
            {"city": "New York", "country": "USA", "isp": "Verizon Communications"},
            {"city": "London", "country": "UK", "isp": "British Telecom"},
            {"city": "Tokyo", "country": "Japan", "isp": "NTT Communications"},
            {"city": "Mumbai", "country": "India", "isp": "Reliance Jio"},
            {"city": "Berlin", "country": "Germany", "isp": "Deutsche Telekom"},
            {"city": "Toronto", "country": "Canada", "isp": "Bell Canada"},
            {"city": "Sydney", "country": "Australia", "isp": "Telstra"},
            {"city": "Singapore", "country": "Singapore", "isp": "Singtel"}
        ]
        
        self.suspicious_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 3389: "RDP", 1433: "SQL Server"
        }
    
    def generate_demo_alerts(self, count=50):
        """Generate realistic demo alerts"""
        alerts = []
        end_time = datetime.now()
        
        for i in range(count):
            # Generate alerts over the last 24 hours
            alert_time = end_time - timedelta(
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59)
            )
            
            threat_type = random.choice(self.threat_types)
            severity = self.get_severity_for_threat(threat_type)
            source_ip = random.choice(self.demo_ips)
            location = random.choice(self.locations)
            
            alert = {
                "timestamp": alert_time.isoformat(),
                "type": threat_type,
                "severity": severity,
                "source_ip": source_ip,
                "destination_ip": "192.168.1.1",
                "description": self.get_description_for_threat(threat_type, source_ip),
                "location": location
            }
            
            # Add payload samples for specific threats
            if threat_type == "SQL_INJECTION":
                alert["payload_sample"] = "' OR '1'='1' --"
            elif threat_type == "XSS_ATTACK":
                alert["payload_sample"] = "<script>alert('XSS')</script>"
            
            alerts.append(alert)
        
        alerts.sort(key=lambda x: x["timestamp"], reverse=True)
        return alerts
    
    def get_severity_for_threat(self, threat_type):
        """Assign realistic severity based on threat type"""
        high_threats = ["SQL_INJECTION", "COMMAND_INJECTION", "MALWARE_SIGNATURES", "BLACKLISTED_IP"]
        medium_threats = ["PORT_SCAN", "HIGH_FREQUENCY", "XSS_ATTACK"]
        
        if threat_type in high_threats:
            return random.choice(["HIGH", "HIGH", "MEDIUM"])
        elif threat_type in medium_threats:
            return random.choice(["MEDIUM", "MEDIUM", "LOW"])
        else:
            return random.choice(["LOW", "MEDIUM"])
    
    def get_description_for_threat(self, threat_type, source_ip):
        """Generate realistic descriptions"""
        descriptions = {
            "PORT_SCAN": f"Port scanning detected from {source_ip} across multiple services",
            "SUSPICIOUS_PORT": f"Access attempted on high-risk service port from {source_ip}",
            "SQL_INJECTION": f"Malicious SQL injection attempt detected from {source_ip}",
            "XSS_ATTACK": f"Cross-site scripting attack vector identified from {source_ip}",
            "COMMAND_INJECTION": f"System command injection attempt blocked from {source_ip}",
            "HIGH_FREQUENCY": f"Abnormal packet frequency from {source_ip} indicating potential DoS",
            "MALWARE_SIGNATURES": f"Suspicious code patterns matching known malware from {source_ip}",
            "BLACKLISTED_IP": f"Traffic detected from known malicious IP address {source_ip}"
        }
        return descriptions.get(threat_type, f"Unknown threat detected from {source_ip}")
    
    def generate_demo_statistics(self, alerts):
        """Generate realistic statistics from demo alerts"""
        total_threats = len(alerts)
        
        # Count by severity and type
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        threat_type_counts = {}
        ip_counts = {}
        
        for alert in alerts:
            severity_counts[alert["severity"]] += 1
            threat_type = alert["type"]
            threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
            source_ip = alert["source_ip"]
            ip_counts[source_ip] = ip_counts.get(source_ip, 0) + 1
        
        # Generate hourly data
        hourly_data = []
        for i in range(24):
            hour_time = datetime.now() - timedelta(hours=i)
            hour_start = hour_time.replace(minute=0, second=0, microsecond=0)
            hour_end = hour_start + timedelta(hours=1)
            
            hour_alerts = [a for a in alerts if 
                          hour_start <= datetime.fromisoformat(a["timestamp"]) < hour_end]
            
            hourly_data.append({
                "hour": hour_time.strftime("%H:00"),
                "count": len(hour_alerts),
                "timestamp": hour_time.strftime("%Y-%m-%d %H:00:00")
            })
        
        # Top source IPs
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_threats": total_threats,
            "severity_breakdown": severity_counts,
            "threat_types": threat_type_counts,
            "hourly_trends": list(reversed(hourly_data)),
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in top_ips]
        }
    
    def generate_live_stats(self):
        """Generate realistic live statistics for dashboard"""
        return {
            "total_packets": random.randint(8000, 15000),
            "total_threats": random.randint(25, 75),
            "active_connections": random.randint(1, 5),
            "threat_rate": f"{random.uniform(0.3, 2.1):.2f}%"
        }
