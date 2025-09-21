import smtplib
import json
import csv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
import os

class AlertSystem:
    def __init__(self, enable_email=False, email_config=None):
        self.enable_email = enable_email
        self.email_config = email_config or {}
        self.log_file = "logs/nids_alerts.csv"
        self.json_log = "logs/nids_alerts.json"
        
        # Create logs directory
        os.makedirs("logs", exist_ok=True)
        
        # Initialize log files
        self.init_csv_log()
    
    def init_csv_log(self):
        """Initialize CSV log file with headers"""
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Type", "Severity", "Source_IP", 
                               "Destination_IP", "Description"])
    
    def send_alert(self, alert):
        """Send alert via multiple channels"""
        # Console alert
        self.console_alert(alert)
        
        # Log to file
        self.log_alert(alert)
        
        # Email alert (if enabled)
        if self.enable_email:
            self.email_alert(alert)
    
    def console_alert(self, alert):
        """Display alert on console with color coding"""
        severity = alert["severity"]
        
        # Color codes for different severities
        colors = {
            "HIGH": "\033[91m",    # Red
            "MEDIUM": "\033[93m",  # Yellow
            "LOW": "\033[94m"      # Blue
        }
        reset_color = "\033[0m"
        
        color = colors.get(severity, "")
        
        print(f"\n{color}🚨 SECURITY ALERT - {severity} SEVERITY 🚨{reset_color}")
        print(f"⏰ Time: {alert['timestamp']}")
        print(f"🔍 Type: {alert['type']}")
        print(f"📍 Source: {alert['source_ip']}")
        print(f"📍 Target: {alert['destination_ip']}")
        print(f"📝 Details: {alert['description']}")
        print("="*60)
    
    def log_alert(self, alert):
        """Log alert to CSV and JSON files"""
        # CSV logging
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                alert["timestamp"],
                alert["type"],
                alert["severity"],
                alert["source_ip"],
                alert["destination_ip"],
                alert["description"]
            ])
        
        # JSON logging
        alerts_list = []
        if os.path.exists(self.json_log):
            with open(self.json_log, 'r') as f:
                try:
                    alerts_list = json.load(f)
                except json.JSONDecodeError:
                    alerts_list = []
        
        alerts_list.append(alert)
        
        with open(self.json_log, 'w') as f:
            json.dump(alerts_list, f, indent=2)
    
    def email_alert(self, alert):
        """Send email notification (optional feature)"""
        try:
            if not all(k in self.email_config for k in ['smtp_server', 'smtp_port', 'username', 'password', 'to_email']):
                return
            
            msg = MIMEMultipart()
            msg['From'] = self.email_config['username']
            msg['To'] = self.email_config['to_email']
            msg['Subject'] = f"NIDS Alert - {alert['severity']} - {alert['type']}"
            
            body = f"""
            Security Alert Detected!
            
            Time: {alert['timestamp']}
            Type: {alert['type']}
            Severity: {alert['severity']}
            Source IP: {alert['source_ip']}
            Target IP: {alert['destination_ip']}
            Description: {alert['description']}
            
            This is an automated alert from your Network Intrusion Detection System.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"📧 Email alert sent for {alert['type']} threat")
            
        except Exception as e:
            print(f"❌ Failed to send email alert: {e}")
