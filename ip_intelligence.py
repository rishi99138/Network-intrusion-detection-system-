import requests
import json
from functools import lru_cache
import time

class IPIntelligence:
    def __init__(self):
        # Free IP geolocation services (no API key needed)
        self.geo_apis = [
            "http://ip-api.com/json/",
            "https://ipapi.co/{}/json/",
            "https://freegeoip.app/json/"
        ]
        
        # Known malicious IP ranges (example - you can expand this)
        self.malicious_ranges = [
            "192.168.1.666",  # Example malicious IP
            "10.0.0.666",     # Another example
        ]
        
        # Cache for IP lookups to avoid rate limiting
        self.ip_cache = {}
    
    @lru_cache(maxsize=100)
    def get_ip_location(self, ip_address):
        """Get geographic location of IP address"""
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
        
        # Skip private IP ranges
        if self.is_private_ip(ip_address):
            return {"country": "Private", "city": "Local Network", "isp": "Private"}
        
        for api_url in self.geo_apis:
            try:
                response = requests.get(api_url.format(ip_address) if "{}" in api_url else api_url + ip_address, 
                                      timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Normalize response format
                    location = {
                        "country": data.get('country', 'Unknown'),
                        "city": data.get('city', 'Unknown'),
                        "isp": data.get('isp', data.get('org', 'Unknown'))
                    }
                    
                    # Cache the result
                    self.ip_cache[ip_address] = location
                    return location
                    
            except Exception as e:
                continue  # Try next API
        
        # Default if all APIs fail
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
    
    def is_private_ip(self, ip):
        """Check if IP is in private ranges"""
        private_ranges = [
            "192.168.", "10.", "172.16.", "172.17.", "172.18.", 
            "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
            "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
            "172.29.", "172.30.", "172.31.", "127."
        ]
        return any(ip.startswith(prefix) for prefix in private_ranges)
    
    def assess_threat_level(self, ip_address, location_data):
        """Assess threat level based on IP characteristics"""
        threat_level = "LOW"
        threat_indicators = []
        
        # Check against known malicious IPs
        if ip_address in self.malicious_ranges:
            threat_level = "HIGH"
            threat_indicators.append("Known malicious IP")
        
        # Geographic risk assessment
        high_risk_countries = ["Unknown", "N/A"]  # Expand as needed
        if location_data.get("country") in high_risk_countries:
            threat_level = "MEDIUM" if threat_level == "LOW" else threat_level
            threat_indicators.append("High-risk geographic location")
        
        # ISP-based assessment
        suspicious_isps = ["tor", "vpn", "proxy", "anonymous"]
        isp = location_data.get("isp", "").lower()
        if any(keyword in isp for keyword in suspicious_isps):
            threat_level = "MEDIUM" if threat_level == "LOW" else threat_level
            threat_indicators.append("Suspicious ISP/Service")
        
        return {
            "threat_level": threat_level,
            "indicators": threat_indicators,
            "location": location_data
        }
