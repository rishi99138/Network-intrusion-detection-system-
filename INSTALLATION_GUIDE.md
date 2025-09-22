# NIDS - Network Intrusion Detection System
## Complete Installation Guide

### 🎯 Overview
This guide will help you install and configure the NIDS on your local network for **real-time monitoring and threat detection**.

**Demo vs. Local:**
- **Online Demo:** Shows interface with sample data
- **Local Install:** Monitors your actual network traffic

---

## 🖥️ System Requirements

### Minimum Requirements
- **OS:** Windows 10/11 (64-bit)
- **Python:** 3.9 or higher
- **RAM:** 4GB minimum, 8GB recommended
- **Privileges:** Administrator access required
- **Network:** Active network interface

### Required Software
- Python 3.9+ ([Download](https://www.python.org/downloads/))
- Git (optional) ([Download](https://git-scm.com/))
- Npcap packet capture library ([Download](https://npcap.com/))

---

## 🚀 Quick Installation

### Step 1: Download NIDS
Option A: Git Clone (Recommended)
git clone https://github.com/rishi99138/Network-intrusion-detection-system-.git
cd Network-intrusion-detection-system-

Option B: Manual Download
Download ZIP from GitHub and extract

### Step 2: Install Python Dependencies
Install required packages
pip install scapy requests flask flask-socketio plotly pandas

Or use requirements file
pip install -r requirements.txt


### Step 3: Install Packet Capture Driver
1. Download **Npcap** from [npcap.com](https://npcap.com/)
2. Install with **"WinPcap API-compatible Mode"** enabled
3. Restart your computer

### Step 4: Run NIDS (Important: Run as Administrator)
Navigate to NIDS directory
cd Network-intrusion-detection-system-

Run main system (AS ADMINISTRATOR)
python integrated_nids_system.py


### Step 5: Access Dashboard
- Open browser: [**http://localhost:5000**](http://localhost:5000)
- Dashboard loads with live monitoring

---

## 🔧 Configuration

### Network Interface Selection
The system auto-detects your network interface. To specify:
Edit integrated_nids_system.py
INTERFACE = "your_interface_name" # e.g., "Ethernet", "Wi-Fi"

### Email Alerts Setup
Edit `enhanced_email_system.py`:
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your-email@gmail.com"
SENDER_PASSWORD = "your-app-password"


### Detection Rules Customization
Modify `detection_engine.py` to add custom rules:
Add new threat patterns
custom_patterns = [
"your-custom-malware-signature",
"suspicious-url-pattern"
]

---

## 🛡️ Features Available Locally

### Real-time Monitoring
- ✅ Live packet capture and analysis
- ✅ Network traffic visualization
- ✅ Bandwidth monitoring

### Threat Detection
- ✅ Port scanning detection
- ✅ SQL injection attempts
- ✅ XSS attack patterns
- ✅ Command injection detection
- ✅ Malware signature matching
- ✅ Suspicious port access
- ✅ High-frequency attack detection

### Alerting & Logging
- ✅ Real-time email notifications
- ✅ JSON and CSV log files
- ✅ Threat severity classification
- ✅ Geographic IP intelligence

### Web Dashboard
- ✅ Professional real-time interface
- ✅ Interactive threat charts
- ✅ Live statistics
- ✅ Recent alerts panel

---

## 🧪 Testing Your Installation

### Generate Test Traffic
Test port scanning detection
nmap -p 21,22,23,80,443 google.com

Test high-frequency detection
ping -t google.com

Test web traffic monitoring
curl -X POST http://httpbin.org/post -d "test=data"


### Verify Detection
1. Check dashboard for new alerts
2. Look for log files in `logs/` directory
3. Check email for notifications (if configured)

---

## 🚨 Troubleshooting

### Common Issues

**"Permission denied" error:**
- Run Command Prompt as Administrator
- Ensure Npcap is installed properly

**"No module named 'scapy'" error:**
pip install scapy --upgrade

**Dashboard not loading:**
- Check if port 5000 is available
- Try: `netstat -an | findstr :5000`

**No packets captured:**
- Verify network interface is active
- Check Npcap installation
- Run with administrator privileges

### Get Help
- **Issues:** [GitHub Issues](https://github.com/rishi99138/Network-intrusion-detection-system-/issues)
- **Documentation:** Check README.md
- **Email:** Support via GitHub

---

## 📊 Performance Tips

### Optimize for Your Network
- Adjust packet capture buffer size
- Configure threat detection sensitivity
- Set appropriate logging levels

### Resource Management
- Monitor CPU and memory usage
- Configure log rotation
- Set packet capture limits

---

## 🔒 Security Considerations

### Network Deployment
- Run on dedicated monitoring machine
- Ensure secure log storage
- Configure firewall exceptions
- Use encrypted email alerts

### Data Protection
- Logs contain network traffic data
- Implement proper access controls
- Consider data retention policies

---

## 📝 License & Support

This project is for educational and security research purposes. 

**Support:** Create an issue on GitHub for bugs or feature requests.

**Contributing:** Pull requests welcome for improvements and new features.

---

*For the online demo with sample data, visit: [https://rishi99138.pythonanywhere.com/]*
Step 3: Update and Deploy
Save the updated dashboard.html on PythonAnywhere

Create the INSTALLATION_GUIDE.md file on your GitHub repository

Reload your web app

Step 4: Test Your Updated Website
Visit your site and you should now see:

✅ Download & Installation Guide section

✅ Feature comparison table

✅ GitHub download buttons

✅ Complete setup instructions