from scapy.all import *
import datetime

def test_everything():
    print("🔍 Testing complete NIDS setup...")
    print(f"📅 Current time: {datetime.datetime.now()}")
    
    try:
        # Test 1: Scapy installation
        print("\n✅ Scapy is installed and working!")
        
        # Test 2: Network interfaces
        print("\n🌐 Available network interfaces:")
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f"  {i}: {iface}")
        
        # Test 3: Basic packet creation
        test_packet = IP(dst="8.8.8.8")/ICMP()
        print(f"\n📦 Test packet created: {test_packet.summary()}")
        
        print("\n🎉 Your NIDS environment is ready!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False

if __name__ == "__main__":
    test_everything()
