from scapy.all import *
import datetime
import os
import threading
import time
from detection_engine import ThreatDetectionEngine
from alert_system import AlertSystem
from payload_analyzer import PayloadAnalyzer
from ip_intelligence import IPIntelligence
from web_dashboard import dashboard, run_dashboard

class ComprehensiveNIDS:
    def __init__(self, enable_dashboard=True):
        self.packet_count = 0
        self.threat_count = 0
        self.start_time = datetime.datetime.now()
        self.monitoring_active = False
        
        # Initialize all detection components
        self.detection_engine = ThreatDetectionEngine()
        self.payload_analyzer = PayloadAnalyzer()
        self.ip_intelligence = IPIntelligence()
        self.alert_system = AlertSystem()
        
        # Dashboard integration
        self.enable_dashboard = enable_dashboard
        self.dashboard = dashboard
        
        if enable_dashboard:
            # Start dashboard in separate thread
            self.dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
            self.dashboard_thread.start()
            print("🌐 Web Dashboard started at http://localhost:5000")
            time.sleep(2)  # Give dashboard time to start
        
        print("🛡️  COMPREHENSIVE NETWORK INTRUSION DETECTION SYSTEM")
        print("="*60)
        print("🔍 Multi-layered Threat Detection: ACTIVE")
        print("🧬 Advanced Payload Analysis: ACTIVE")
        print("🌍 IP Geolocation Intelligence: ACTIVE")
        print("📊 Real-time Web Dashboard: ACTIVE" if enable_dashboard else "DISABLED")
        print("📈 Live Threat Visualization: ACTIVE" if enable_dashboard else "DISABLED")
    
    def comprehensive_packet_analysis(self, packet):
        """Complete packet analysis with dashboard integration"""
        self.packet_count += 1
        all_alerts = []
        
        # Update live statistics
        if self.enable_dashboard:
            self.dashboard.live_stats['total_packets'] = self.packet_count
        
        # Layer 1: Network-level detection
        network_alerts = self.detection_engine.analyze_packet(packet)
        all_alerts.extend(network_alerts)
        
        # Layer 2: Payload analysis
        payload_alerts = self.payload_analyzer.analyze_payload(packet)
        all_alerts.extend(payload_alerts)
        
        # Process all alerts
        for alert in all_alerts:
            self.threat_count += 1
            
            # Enhanced threat context
            location_info = None
            try:
                location_data = self.ip_intelligence.get_ip_location(alert['source_ip'])
                location_info = self.ip_intelligence.assess_threat_level(
                    alert['source_ip'], location_data)
                # Add location to alert
                alert['location'] = location_info
            except:
                pass
            
            # Console alert
            self.enhanced_console_alert(alert, location_info)
            
            # Log alert
            self.alert_system.log_alert(alert)
            
            # Update dashboard with new alert
            if self.enable_dashboard:
                self.dashboard.alerts_data.append(alert)
                self.dashboard.live_stats['total_threats'] = self.threat_count
                
                # Keep only recent alerts in memory (last 1000)
                if len(self.dashboard.alerts_data) > 1000:
                    self.dashboard.alerts_data = self.dashboard.alerts_data[-1000:]
        
        # Progress updates
        if self.packet_count % 50 == 0:
            print(f"[📊 Analyzed: {self.packet_count} packets | Threats: {self.threat_count}]")
            if self.enable_dashboard:
                threat_rate = (self.threat_count / self.packet_count) * 100 if self.packet_count > 0 else 0
                self.dashboard.live_stats['threat_rate'] = f"{threat_rate:.2f}%"
    
    def enhanced_console_alert(self, alert, location_info=None):
        """Enhanced console alert with dashboard integration notice"""
        severity = alert["severity"]
        colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
        reset = "\033[0m"
        color = colors.get(severity, "")
        
        print(f"\n{color}🚨 COMPREHENSIVE NIDS ALERT - {severity} SEVERITY 🚨{reset}")
        print(f"⏰ Time: {alert['timestamp']}")
        print(f"🔍 Type: {alert['type']}")
        print(f"📍 Source: {alert['source_ip']}")
        
        if location_info:
            loc = location_info['location']
            print(f"🌍 Location: {loc['city']}, {loc['country']} ({loc['isp']})")
        
        print(f"📝 Details: {alert['description']}")
        
        if self.enable_dashboard:
            print("🌐 Alert added to real-time dashboard")
        
        print("="*70)
    
    def start_comprehensive_monitoring(self, interface=None, count=200, duration=None):
        """Start comprehensive NIDS monitoring with dashboard"""
        self.monitoring_active = True
        
        print(f"\n🚀 Starting Comprehensive NIDS Monitoring")
        print(f"📊 Target: {count} packets" + (f" | {duration}s duration" if duration else ""))
        print(f"⏰ Started: {self.start_time.strftime('%H:%M:%S')}")
        
        if self.enable_dashboard:
            print(f"🌐 Live Dashboard: http://localhost:5000")
            print("📈 Real-time threat visualization available")
        
        print("\n" + "="*70)
        print("🔍 COMPREHENSIVE THREAT DETECTION ACTIVE...")
        print("="*70)
        
        try:
            if duration:
                sniff(iface=interface, prn=self.comprehensive_packet_analysis, 
                      timeout=duration, stop_filter=lambda p: not self.monitoring_active)
            else:
                sniff(iface=interface, prn=self.comprehensive_packet_analysis, 
                      count=count, stop_filter=lambda p: not self.monitoring_active)
                
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Error: {e}")
        finally:
            self.monitoring_active = False
        
        self.generate_comprehensive_report()
    
    def generate_comprehensive_report(self):
        """Generate final comprehensive report"""
        end_time = datetime.datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # Get all statistics
        network_stats = self.detection_engine.get_statistics()
        payload_stats = self.payload_analyzer.get_payload_statistics()
        
        print("\n" + "="*70)
        print("📈 COMPREHENSIVE NIDS FINAL REPORT")
        print("="*70)
        print(f"⏱️  Session Duration: {duration:.1f} seconds")
        print(f"📊 Total Packets Analyzed: {self.packet_count}")
        print(f"🚨 Total Threats Detected: {self.threat_count}")
        print(f"📈 Threat Detection Rate: {(self.threat_count/self.packet_count)*100:.2f}%" if self.packet_count > 0 else "0%")
        
        if self.enable_dashboard:
            print(f"🌐 Web Dashboard: http://localhost:5000 (Running)")
            print(f"📊 Real-time Visualizations: Available")
        
        if network_stats['total_alerts'] > 0:
            print(f"\n🔍 Network Threat Breakdown:")
            for threat_type, count in network_stats['alert_breakdown'].items():
                print(f"   • {threat_type}: {count}")
        
        if payload_stats:
            print(f"\n🧬 Payload Threat Breakdown:")
            for threat_type, count in payload_stats.items():
                print(f"   • {threat_type}: {count}")
        
        print(f"\n📁 Complete logs available at:")
        print(f"   • logs/nids_alerts.csv")
        print(f"   • logs/nids_alerts.json")
        
        if self.threat_count == 0:
            print("\n✅ No security threats detected - Network appears secure!")
        else:
            print(f"\n⚠️  {self.threat_count} potential security threats identified!")
            if self.enable_dashboard:
                print("🌐 View detailed analysis on the web dashboard")

if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    
    print("🛡️  LAUNCHING COMPREHENSIVE NIDS WITH WEB DASHBOARD")
    print("="*60)
    
    # Create comprehensive NIDS with dashboard
    nids = ComprehensiveNIDS(enable_dashboard=True)
    
    # Start monitoring
    print("\n⏳ Starting in 3 seconds... Open http://localhost:5000 in your browser!")
    time.sleep(3)
    
    nids.start_comprehensive_monitoring(count=100)

