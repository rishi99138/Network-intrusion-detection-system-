import flask
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import pandas as pd
import plotly.graph_objs as go
import plotly.utils
from datetime import datetime, timedelta
import threading
import queue
import os
import csv

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_dashboard_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

class NIDSDashboard:
    def __init__(self):
        self.alert_queue = queue.Queue()
        self.alerts_data = []
        self.live_stats = {
            'total_packets': 0,
            'total_threats': 0,
            'active_connections': 0,
            'threat_rate': 0
        }
        self.load_existing_alerts()
    
    def load_existing_alerts(self):
        """Load existing alerts from log files"""
        try:
            if os.path.exists('logs/nids_alerts.json'):
                with open('logs/nids_alerts.json', 'r') as f:
                    self.alerts_data = json.load(f)
                    # Keep only recent alerts (last 24 hours)
                    cutoff_time = datetime.now() - timedelta(hours=24)
                    self.alerts_data = [
                        alert for alert in self.alerts_data 
                        if datetime.fromisoformat(alert['timestamp']) > cutoff_time
                    ]
        except Exception as e:
            print(f"Error loading alerts: {e}")
            self.alerts_data = []
    
    def get_threat_statistics(self):
        """Calculate comprehensive threat statistics"""
        if not self.alerts_data:
            return {
                'severity_breakdown': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
                'threat_types': {},
                'hourly_trends': [],
                'top_source_ips': [],
                'geographic_threats': []
            }
        
        # Severity breakdown
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        threat_types = {}
        hourly_data = {}
        source_ip_counts = {}
        
        for alert in self.alerts_data:
            # Count by severity
            severity = alert.get('severity', 'LOW')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by threat type
            threat_type = alert.get('type', 'UNKNOWN')
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Hourly trends
            try:
                timestamp = datetime.fromisoformat(alert['timestamp'])
                hour_key = timestamp.strftime('%H:00')
                hourly_data[hour_key] = hourly_data.get(hour_key, 0) + 1
            except:
                pass
            
            # Source IP frequency
            source_ip = alert.get('source_ip', 'Unknown')
            source_ip_counts[source_ip] = source_ip_counts.get(source_ip, 0) + 1
        
        # Top source IPs
        top_ips = sorted(source_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Hourly trends (last 24 hours)
        current_time = datetime.now()
        hourly_trends = []
        for i in range(24):
            hour_time = current_time - timedelta(hours=i)
            hour_key = hour_time.strftime('%H:00')
            count = hourly_data.get(hour_key, 0)
            hourly_trends.append({
                'hour': hour_key,
                'count': count,
                'timestamp': hour_time.strftime('%Y-%m-%d %H:00:00')
            })
        
        return {
            'severity_breakdown': severity_counts,
            'threat_types': dict(list(threat_types.items())[:10]),  # Top 10 types
            'hourly_trends': list(reversed(hourly_trends)),
            'top_source_ips': [{'ip': ip, 'count': count} for ip, count in top_ips],
            'total_threats': len(self.alerts_data)
        }
    
    def create_threat_visualizations(self):
        """Create Plotly visualizations for threats"""
        stats = self.get_threat_statistics()
        
        # Severity Pie Chart
        severity_fig = go.Figure(data=[go.Pie(
            labels=list(stats['severity_breakdown'].keys()),
            values=list(stats['severity_breakdown'].values()),
            marker_colors=['#ff4444', '#ffaa44', '#4444ff']
        )])
        severity_fig.update_layout(
            title='Threat Severity Distribution',
            font=dict(size=12),
            height=300
        )
        
        # Hourly Trends Line Chart
        hourly_fig = go.Figure(data=go.Scatter(
            x=[item['hour'] for item in stats['hourly_trends']],
            y=[item['count'] for item in stats['hourly_trends']],
            mode='lines+markers',
            line=dict(color='#ff6666', width=3),
            marker=dict(size=6)
        ))
        hourly_fig.update_layout(
            title='Threat Activity - Last 24 Hours',
            xaxis_title='Hour',
            yaxis_title='Threat Count',
            height=300
        )
        
        # Threat Types Bar Chart
        threat_types_fig = go.Figure(data=[go.Bar(
            x=list(stats['threat_types'].keys()),
            y=list(stats['threat_types'].values()),
            marker_color='#66b3ff'
        )])
        threat_types_fig.update_layout(
            title='Threat Types Distribution',
            xaxis_title='Threat Type',
            yaxis_title='Count',
            height=300
        )
        
        return {
            'severity_chart': json.dumps(severity_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'hourly_chart': json.dumps(hourly_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'threats_chart': json.dumps(threat_types_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'statistics': stats
        }

# Global dashboard instance
dashboard = NIDSDashboard()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/dashboard-data')
def dashboard_data():
    """API endpoint for dashboard data"""
    charts = dashboard.create_threat_visualizations()
    return jsonify(charts)

@app.route('/api/recent-alerts')
def recent_alerts():
    """Get recent alerts"""
    recent = dashboard.alerts_data[-20:] if dashboard.alerts_data else []
    return jsonify(recent)

@app.route('/api/live-stats')
def live_stats():
    """Get live statistics"""
    return jsonify(dashboard.live_stats)

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected to dashboard')
    emit('status', {'msg': 'Connected to NIDS Dashboard'})

def run_dashboard():
    """Start the dashboard server"""
    print("🌐 Starting NIDS Web Dashboard...")
    print("📊 Access dashboard at: http://localhost:5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

if __name__ == '__main__':
    run_dashboard()
