from scapy.all import *
import datetime
import os
from detection_engine import ThreatDetectionEngine
from alert_system import AlertSystem
from payload_analyzer import PayloadAnalyzer
from ip_intelligence import IPIntelligence
from enhanced_email_system import EnhancedEmailSystem

class AdvancedNetworkIDS:
    def __init__(self, enable_email=False, email_config=None):
        self.packet_count = 0
        self.threat_count = 0
        self.payload_threats = 0
        self.start_time = datetime.datetime.now()
        
        # Initialize all detection components
        self.detection_engine = ThreatDetectionEngine()
        self.payload_analyzer = PayloadAnalyzer()
        self.ip_intelligence = IPIntelligence()
        
        # Enhanced alert system
        self.alert_system = AlertSystem(enable_email, email_config)
        
        # Email system
        if enable_email and email_config:
            self.email_system = EnhancedEmailSystem(email_config)
        else:
            self.email_system = None
        
        print("🛡️  ADVANCED NETWORK INTRUSION DETECTION SYSTEM v3.0")
        print("="*60)
        print("🔍 Multi-layered Threat Detection: ACTIVE")
        print("🧬 Payload Analysis Engine: ACTIVE")
        print("🌍 IP Geolocation Intelligence: ACTIVE")
        if enable_email:
            print("📧 Enhanced Email Alerts: ENABLED")
        print("📊 Advanced Logging & Reporting: ACTIVE")
    
    def advanced_packet_analysis(self, packet):
        """Comprehensive packet analysis with all detection layers"""
        self.packet_count += 1
        all_alerts = []
        
        # Layer 1: Network-level threat detection
        network_alerts = self.detection_engine.analyze_packet(packet)
        all_alerts.extend(network_alerts)
        
        # Layer 2: Payload analysis
        payload_alerts = self.payload_analyzer.analyze_payload(packet)
        if payload_alerts:
            self.payload_threats += len(payload_alerts)
            all_alerts.extend(payload_alerts)
        
        # Process all alerts with enhanced intelligence
        for alert in all_alerts:
            self.threat_count += 1
            
            # Get IP intelligence for source
            location_info = None
            try:
                location_data = self.ip_intelligence.get_ip_location(alert['source_ip'])
                location_info = self.ip_intelligence.assess_threat_level(
                    alert['source_ip'], location_data)
            except:
                pass  # Continue without location data
            
            # Enhanced console alert with location
            self.enhanced_console_alert(alert, location_info)
            
            # Log alert
            self.alert_system.log_alert(alert)
            
            # Send email if configured and high severity
            if (self.email_system and 
                alert['severity'] in ['HIGH', 'CRITICAL']):
                self.email_system.send_email_alert(alert, location_info)
        
        # Progress indicator
        if self.packet_count % 25 == 0:
            print(f"[📊 Analyzed: {self.packet_count} packets | Threats: {self.threat_count}]")
    
    def enhanced_console_alert(self, alert, location_info=None):
        """Enhanced console alert with geographic information"""
        severity = alert["severity"]
        colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        reset = "\033[0m"
        color = colors.get(severity, "")
        
        print(f"\n{color}🚨 ADVANCED SECURITY ALERT - {severity} SEVERITY 🚨{reset}")
        print(f"⏰ Time: {alert['timestamp']}")
        print(f"🔍 Type: {alert['type']}")
        print(f"📍 Source: {alert['source_ip']}")
        
        # Add location information
        if location_info:
            loc = location_info['location']
            print(f"🌍 Location: {loc['city']}, {loc['country']} ({loc['isp']})")
            if location_info['threat_level'] != 'LOW':
                print(f"⚠️  Risk Level: {location_info['threat_level']}")
        
        print(f"📍 Target: {alert['destination_ip']}")
        print(f"📝 Details: {alert['description']}")
        
        # Show payload info if available
        if 'payload_sample' in alert:
            print(f"🔍 Payload: {alert['payload_sample'][:50]}...")
        
        print("="*70)
    
    def start_advanced_monitoring(self, interface=None, count=100, duration=None):
        """Start advanced NIDS monitoring"""
        print(f"\n🚀 Starting Advanced NIDS Monitoring")
        print(f"📊 Analysis Target: {count} packets" + (f" | {duration}s duration" if duration else ""))
        print(f"⏰ Started: {self.start_time.strftime('%H:%M:%S')}")
        print("\n" + "="*70)
        print("🔍 MULTI-LAYER THREAT DETECTION ACTIVE...")
        print("="*70)
        
        try:
            if duration:
                sniff(iface=interface, prn=self.advanced_packet_analysis, timeout=duration)
            else:
                sniff(iface=interface, prn=self.advanced_packet_analysis, count=count)
                
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        self.generate_advanced_report()
    
    def generate_advanced_report(self):
        """Generate comprehensive analysis report"""
        end_time = datetime.datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Get all statistics
        network_stats = self.detection_engine.get_statistics()
        payload_stats = self.payload_analyzer.get_payload_statistics()
        
        print("\n" + "="*70)
        print("📈 ADVANCED NIDS MONITORING REPORT")
        print("="*70)
        print(f"⏱️  Session Duration: {duration:.1f} seconds")
        print(f"📊 Total Packets Analyzed: {self.packet_count}")
        print(f"🚨 Total Threats Detected: {self.threat_count}")
        print(f"🔍 Network-level Threats: {network_stats['total_alerts']}")
        print(f"🧬 Payload-level Threats: {self.payload_threats}")
        
        if network_stats['total_alerts'] > 0:
            print(f"\n🔍 Network Threat Breakdown:")
            for threat_type, count in network_stats['alert_breakdown'].items():
                print(f"   • {threat_type}: {count}")
        
        if payload_stats:
            print(f"\n🧬 Payload Threat Breakdown:")
            for threat_type, count in payload_stats.items():
                print(f"   • {threat_type}: {count}")
        
        print(f"\n📁 All alerts logged to:")
        print(f"   • logs/nids_alerts.csv")
        print(f"   • logs/nids_alerts.json")
        
        if self.threat_count == 0:
            print("\n✅ No security threats detected - Network appears clean!")
        else:
            print(f"\n⚠️  {self.threat_count} potential security threats identified!")

# Email configuration (update with your details)
EMAIL_CONFIG = {
    'enabled': False,  # Set to True to enable email alerts
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'from_email': 'your_nids@gmail.com',
    'password': 'your_app_password',  # Use App Password for Gmail
    'to_email': 'security_team@company.com'
}

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Create advanced NIDS
    nids = AdvancedNetworkIDS(
        enable_email=EMAIL_CONFIG['enabled'], 
        email_config=EMAIL_CONFIG if EMAIL_CONFIG['enabled'] else None
    )
    
    # Start monitoring
    nids.start_advanced_monitoring(count=60)
