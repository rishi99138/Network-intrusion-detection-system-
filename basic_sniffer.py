from scapy.all import *
import datetime
import os

class NIDSFoundation:
    def __init__(self):
        self.packet_count = 0
        self.ipv4_count = 0
        self.ipv6_count = 0
        self.start_time = datetime.datetime.now()
        
    def packet_handler(self, packet):
        """Process each captured packet - now handles both IPv4 and IPv6"""
        self.packet_count += 1
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Handle both IPv4 and IPv6
        if IP in packet:  # IPv4 packet
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ip_version = "IPv4"
            self.ipv4_count += 1
            
        elif IPv6 in packet:  # IPv6 packet
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            ip_version = "IPv6"
            self.ipv6_count += 1
            
        else:
            return  # Skip non-IP packets
        
        print(f"\n[{timestamp}] Packet #{self.packet_count}")
        print(f"IP Version: {ip_version}")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        # Protocol-specific information (works for both IPv4/IPv6)
        if TCP in packet:
            print(f"Protocol: TCP")
            print(f"Ports: {packet[TCP].sport} → {packet[TCP].dport}")
            
        elif UDP in packet:
            print(f"Protocol: UDP") 
            print(f"Ports: {packet[UDP].sport} → {packet[UDP].dport}")
            
        elif ICMP in packet:
            print(f"Protocol: ICMP (IPv4)")
            
        elif ICMPv6 in packet:
            print(f"Protocol: ICMPv6 (IPv6)")
            
        print("-" * 40)
    
    def start_monitoring(self, interface=None, count=30):
        """Start packet capture - now captures both IPv4 and IPv6"""
        print(f"🚀 Starting Enhanced NIDS monitoring...")
        print(f"📊 Capturing {count} packets (IPv4 + IPv6)")
        print(f"⏰ Started at: {self.start_time.strftime('%H:%M:%S')}")
        
        if interface:
            print(f"🌐 Interface: {interface}")
        
        print("\n" + "="*50)
        
        try:
            # Remove the "ip" filter to capture both IPv4 and IPv6
            sniff(iface=interface, prn=self.packet_handler, count=count)
            
        except PermissionError:
            print("❌ Permission denied! Run as administrator.")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        # Enhanced summary with IPv4/IPv6 breakdown
        end_time = datetime.datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        print("\n" + "="*50)
        print(f"📈 ENHANCED MONITORING COMPLETE")
        print(f"📊 Total packets captured: {self.packet_count}")
        print(f"🔢 IPv4 packets: {self.ipv4_count}")
        print(f"🔢 IPv6 packets: {self.ipv6_count}")
        print(f"⏱️  Duration: {duration:.1f} seconds")
        if duration > 0:
            print(f"🔢 Rate: {self.packet_count/duration:.1f} packets/second")

if __name__ == "__main__":
    # Clear screen for clean output
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Create and start enhanced NIDS
    nids = NIDSFoundation()
    nids.start_monitoring(count=30)
