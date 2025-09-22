# Network Intrusion Detection System (NIDS)

A comprehensive real-time network security monitoring system built with Python. This system provides advanced threat detection, network traffic analysis, and a professional web-based dashboard for cybersecurity monitoring.

## Overview

The Network Intrusion Detection System is designed to monitor network traffic in real-time, detect various types of security threats, and provide actionable intelligence through an intuitive web interface. The system combines packet-level analysis with machine learning techniques to identify potential security breaches and suspicious network activities.

**Live Demo:** [https://rishi99138.pythonanywhere.com](https://rishi99138.pythonanywhere.com)

**Note:** The online demo displays sample data for demonstration purposes. For actual network monitoring, local installation is required.

## Key Features

### Real-Time Monitoring
- Live packet capture and analysis
- Network traffic visualization
- Bandwidth monitoring and statistics
- Connection tracking and analysis

### Advanced Threat Detection
- Port scanning detection
- SQL injection attempt identification
- Cross-site scripting (XSS) pattern recognition
- Command injection detection
- Malware signature matching
- Suspicious port access monitoring
- High-frequency attack detection
- Blacklisted IP identification

### Professional Dashboard
- Modern web-based interface
- Interactive threat visualization charts
- Real-time statistics and metrics
- Historical trend analysis
- Responsive design for multiple devices

### Alerting and Reporting
- Email notification system
- JSON and CSV log file generation
- Threat severity classification
- Geographic IP intelligence integration
- Detailed incident reporting

## System Architecture

The NIDS consists of several integrated components:

- **Packet Capture Engine**: Real-time network packet interception using Scapy
- **Detection Engine**: Multi-pattern threat analysis system
- **Alert System**: Email and log-based notification framework
- **Web Dashboard**: Flask-based real-time monitoring interface
- **IP Intelligence**: Geographic and threat intelligence integration
- **Data Storage**: JSON/CSV logging with rotation capabilities

## Technical Requirements

### System Requirements
- Operating System: Windows 10/11 (64-bit)
- Python: Version 3.9 or higher
- Memory: 4GB RAM minimum (8GB recommended)
- Network: Active network interface
- Privileges: Administrator access required

### Dependencies
- Scapy (packet manipulation)
- Flask (web framework)
- Flask-SocketIO (real-time communication)
- Plotly (data visualization)
- Pandas (data analysis)
- Requests (HTTP operations)

### Additional Software
- Npcap (Windows packet capture driver)
- Git (for version control)

## Installation

### Quick Setup

1. **Clone the repository:**
git clone https://github.com/rishi99138/Network-intrusion-detection-system-.git
cd Network-intrusion-detection-system-

2. **Install Python dependencies:**
pip install -r requirements.txt


3. **Install Npcap packet capture driver:**
   - Download from [npcap.com](https://npcap.com/)
   - Install with "WinPcap API-compatible Mode" enabled
   - Restart system after installation

4. **Run the NIDS (as Administrator):**
python integrated_nids_system.py


5. **Access the dashboard:**
   - Open browser to `http://localhost:5000`
   - Monitor real-time network security events

### Detailed Installation Guide

For comprehensive installation instructions, system configuration, and troubleshooting, refer to [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md).

## Configuration

### Network Interface Selection
The system automatically detects network interfaces. To specify a particular interface:

Edit integrated_nids_system.py
INTERFACE = "Ethernet" # or your preferred interface name

### Email Alert Configuration
Configure email notifications by editing `enhanced_email_system.py`:

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your-email@gmail.com"
SENDER_PASSWORD = "your-app-password"
RECIPIENT_EMAIL = "admin@company.com"


### Custom Detection Rules
Add custom threat patterns in `detection_engine.py`:

custom_signatures = [
"malicious-pattern-here",
"suspicious-url-pattern",
"custom-attack-signature"
]

## Usage

### Starting the System
Run with administrator privileges for full packet capture capabilities:

Windows Command Prompt (Run as Administrator)
python integrated_nids_system.py

### Dashboard Access
Navigate to `http://localhost:5000` to access the monitoring dashboard featuring:
- Real-time threat statistics
- Interactive security charts
- Live alert feed
- Network activity graphs
- System performance metrics

### Testing Detection Capabilities
Generate test traffic to verify detection:

Port scan detection
nmap -p 21,22,23,80,443 target-host

High-frequency traffic
ping -t target-host

Web application testing
curl -X POST http://target/endpoint -d "test=data"

## File Structure

Network-intrusion-detection-system-/
├── integrated_nids_system.py # Main system controller
├── detection_engine.py # Threat detection logic
├── web_dashboard.py # Dashboard web interface
├── enhanced_email_system.py # Email notification system
├── ip_intelligence.py # Geographic IP analysis
├── payload_analyzer.py # Deep packet inspection
├── demo_data_generator.py # Demo mode data generator
├── templates/
│ └── dashboard.html # Dashboard HTML template
├── logs/ # System log files
├── requirements.txt # Python dependencies
├── INSTALLATION_GUIDE.md # Detailed setup guide
└── README.md # This file

## Security Considerations

### Network Deployment
- Deploy on dedicated monitoring infrastructure
- Implement secure log storage practices
- Configure appropriate firewall rules
- Use encrypted channels for alert notifications

### Data Protection
- Network traffic logs contain sensitive information
- Implement proper access controls
- Consider data retention and privacy policies
- Ensure compliance with organizational security standards

## Performance Optimization

### System Tuning
- Adjust packet capture buffer sizes based on network load
- Configure detection rule sensitivity for your environment
- Implement log rotation to manage storage requirements
- Monitor system resource utilization

### Scalability Considerations
- Database integration for large-scale deployments
- Distributed monitoring for multiple network segments
- Load balancing for high-traffic environments
- Integration with SIEM systems

## Troubleshooting

### Common Issues

**Permission Errors:**
- Ensure running with administrator privileges
- Verify Npcap installation and driver status

**Module Import Errors:**
- Confirm all dependencies are installed: `pip install -r requirements.txt`
- Check Python version compatibility

**Network Interface Issues:**
- Verify network interface is active and accessible
- Confirm Npcap driver is properly installed
- Check interface naming in system configuration

**Dashboard Access Problems:**
- Ensure port 5000 is available and not blocked by firewall
- Verify Flask service is running without errors
- Check browser console for JavaScript errors

## Contributing

Contributions are welcome for bug fixes, feature enhancements, and documentation improvements. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate testing
4. Submit a pull request with detailed description

## License

This project is developed for educational and security research purposes. Please ensure compliance with local laws and organizational policies when deploying in production environments.

## Support

For technical support, bug reports, or feature requests:
- Create an issue on GitHub
- Provide detailed system information and error logs
- Include steps to reproduce any problems

## Acknowledgments

This project utilizes several open-source libraries and tools:
- Scapy for packet manipulation
- Flask for web framework
- Plotly for data visualization
- Bootstrap for UI components

---

**Note:** This system is designed for legitimate security monitoring purposes. Users are responsible for ensuring compliance with applicable laws and regulations regarding network monitoring and data privacy.
