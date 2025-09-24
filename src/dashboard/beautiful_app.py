import dash
from dash import dcc, html, Input, Output, State, dash_table, callback
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
import json
from typing import List, Dict, Any

from src.models.schemas import Alert, SeverityLevel, AlertStatus, ProcessingStats
from src.core.config import config

class BeautifulSIEMDashboard:
    """🛡️ Beautiful SOC Dashboard for SIEM-Fusion"""
    
    def __init__(self):
        self.app = dash.Dash(__name__, external_stylesheets=[
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
            'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap'
        ])
        
        # Add beautiful custom CSS
        self.app.index_string = '''
        <!DOCTYPE html>
        <html>
            <head>
                {%metas%}
                <title>🛡️ SIEM-Fusion SOC Dashboard</title>
                {%favicon%}
                {%css%}
                <style>
                    * {
                        margin: 0;
                        padding: 0;
                        box-sizing: border-box;
                    }
                    
                    body {
                        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        color: #2c3e50;
                    }
                    
                    .dashboard-container {
                        background: rgba(255, 255, 255, 0.95);
                        backdrop-filter: blur(13px);
                        border-radius: 13px;
                        margin: 13px;
                        padding: 20px;
                        box-shadow: 0 13px 27px rgba(0, 0, 0, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .header {
                        background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                        color: white;
                        padding: 17px 20px;
                        border-radius: 10px;
                        margin-bottom: 20px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        box-shadow: 0 7px 20px rgba(44, 62, 80, 0.3);
                    }
                    
                    .header-title {
                        font-size: 1.5em;
                        font-weight: 700;
                        margin: 0;
                        display: flex;
                        align-items: center;
                        color: white;
                    }
                    
                    .header-controls {
                        display: flex;
                        align-items: center;
                        gap: 13px;
                    }
                    
                    .refresh-btn {
                        background: linear-gradient(135deg, #3498db, #2980b9);
                        border: none;
                        color: white;
                        padding: 8px 16px;
                        border-radius: 17px;
                        cursor: pointer;
                        font-weight: 600;
                        transition: all 0.3s ease;
                        box-shadow: 0 3px 10px rgba(52, 152, 219, 0.3);
                    }
                    
                    .refresh-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 25px rgba(52, 152, 219, 0.4);
                    }
                    
                    .stats-row {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(147px, 1fr));
                        gap: 13px;
                        margin-bottom: 20px;
                    }
                    
                    .stat-card {
                        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
                        border-radius: 10px;
                        padding: 17px;
                        box-shadow: 0 7px 20px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                        transition: all 0.3s ease;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .stat-card:hover {
                        transform: translateY(-3px);
                        box-shadow: 0 13px 27px rgba(0, 0, 0, 0.12);
                    }
                    
                    .stat-card::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        height: 3px;
                        background: var(--card-color, #3498db);
                    }
                    
                    .stat-content {
                        display: flex;
                        align-items: center;
                        gap: 13px;
                    }
                    
                    .stat-icon {
                        font-size: 2em;
                        opacity: 0.8;
                    }
                    
                    .stat-text h3 {
                        font-size: 1.7em;
                        font-weight: 700;
                        margin: 0;
                        color: #2c3e50;
                    }
                    
                    .stat-text p {
                        font-size: 0.6em;
                        color: #7f8c8d;
                        margin: 3px 0 0 0;
                        font-weight: 500;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    
                    .charts-row {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 20px;
                        margin-bottom: 20px;
                    }
                    
                    .chart-container {
                        background: white;
                        border-radius: 10px;
                        padding: 13px;
                        box-shadow: 0 7px 20px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                    }
                    
                    .filters-row {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(134px, 1fr));
                        gap: 13px;
                        margin-bottom: 20px;
                        background: white;
                        padding: 17px;
                        border-radius: 10px;
                        box-shadow: 0 7px 20px rgba(0, 0, 0, 0.08);
                    }
                    
                    .filter-group label {
                        font-weight: 600;
                        color: #2c3e50;
                        margin-bottom: 5px;
                        display: block;
                        font-size: 0.9em;
                    }
                    
                    .alerts-section {
                        background: white;
                        border-radius: 10px;
                        padding: 20px;
                        box-shadow: 0 7px 20px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                    }
                    
                    .alerts-section h3 {
                        color: #2c3e50;
                        font-weight: 700;
                        margin-bottom: 13px;
                        font-size: 1em;
                    }
                    
                    .last-update {
                        color: rgba(255, 255, 255, 0.8);
                        font-size: 0.6em;
                        font-weight: 500;
                    }
                    
                    /* Responsive design */
                    @media (max-width: 768px) {
                        .charts-row {
                            grid-template-columns: 1fr;
                        }
                        
                        .header {
                            flex-direction: column;
                            gap: 10px;
                            text-align: center;
                        }
                        
                        .header-title {
                            font-size: 1.2em;
                        }
                    }
                </style>
            </head>
            <body>
                {%app_entry%}
                <footer>
                    {%config%}
                    {%scripts%}
                    {%renderer%}
                </footer>
            </body>
        </html>
        '''
        
        # Dashboard configuration
        self.refresh_interval = config.dashboard_config.get('refresh_interval', 10) * 1000
        self.max_alerts_display = config.dashboard_config.get('max_alerts_display', 50)
        
        # Mock data storage
        self.alerts: List[Alert] = []
        self.stats = ProcessingStats()
        
        self._setup_layout()
        self._setup_callbacks()
    
    def _setup_layout(self):
        """Setup the beautiful dashboard layout"""
        self.app.layout = html.Div([
            html.Div([
                # Beautiful Header
                html.Div([
                    html.H1([
                        html.I(className="fas fa-shield-alt", style={'margin-right': '15px', 'color': '#3498db'}),
                        "SIEM-Fusion SOC Dashboard"
                    ], className="header-title"),
                    html.Div([
                        html.Span(id="last-update", className="last-update"),
                        html.Button([
                            html.I(className="fas fa-sync-alt", style={'margin-right': '8px'}),
                            "Refresh"
                        ], id="refresh-btn", className="refresh-btn")
                    ], className="header-controls")
                ], className="header"),
            
                # Auto-refresh component
                dcc.Interval(
                    id='interval-component',
                    interval=self.refresh_interval,
                    n_intervals=0
                ),
                
                # Beautiful Statistics Cards
                html.Div([
                    self._create_beautiful_stat_card("Dataset Entries", "dataset-entries", "📊", "#3498db"),
                    self._create_beautiful_stat_card("Total Alerts", "total-alerts", "🚨", "#e74c3c"),
                    self._create_beautiful_stat_card("Critical", "critical-alerts", "🔥", "#c0392b"),
                    self._create_beautiful_stat_card("High", "high-alerts", "⚠️", "#e67e22"),
                    self._create_beautiful_stat_card("Medium", "medium-alerts", "📊", "#f39c12"),
                    self._create_beautiful_stat_card("Low", "low-alerts", "✅", "#27ae60")
                ], className="stats-row"),
                
                # Beautiful Charts
                html.Div([
                    html.Div([
                        dcc.Graph(id="severity-chart")
                    ], className="chart-container"),
                    html.Div([
                        dcc.Graph(id="timeline-chart")
                    ], className="chart-container")
                ], className="charts-row"),
                
                # Beautiful Filters
                html.Div([
                    html.Div([
                        html.Label("🎯 Filter by Severity:"),
                        dcc.Dropdown(
                            id="severity-filter",
                            options=[
                                {'label': '🔍 All Severities', 'value': 'all'},
                                {'label': '🔥 Critical', 'value': 'critical'},
                                {'label': '⚠️ High', 'value': 'high'},
                                {'label': '📊 Medium', 'value': 'medium'},
                                {'label': '✅ Low', 'value': 'low'}
                            ],
                            value='all',
                            className="filter-dropdown"
                        )
                    ], className="filter-group"),
                    html.Div([
                        html.Label("📋 Filter by Status:"),
                        dcc.Dropdown(
                            id="status-filter",
                            options=[
                                {'label': '📊 All Status', 'value': 'all'},
                                {'label': '🆕 New', 'value': 'new'},
                                {'label': '🔍 Investigating', 'value': 'investigating'},
                                {'label': '✅ Resolved', 'value': 'resolved'}
                            ],
                            value='all',
                            className="filter-dropdown"
                        )
                    ], className="filter-group"),
                    html.Div([
                        html.Label("⏰ Time Range:"),
                        dcc.Dropdown(
                            id="time-filter",
                            options=[
                                {'label': '⏰ Last Hour', 'value': '1h'},
                                {'label': '🕕 Last 6 Hours', 'value': '6h'},
                                {'label': '📅 Last 24 Hours', 'value': '24h'},
                                {'label': '📆 Last 7 Days', 'value': '7d'}
                            ],
                            value='24h',
                            className="filter-dropdown"
                        )
                    ], className="filter-group")
                ], className="filters-row"),
                
                # Beautiful Alerts Table
                html.Div([
                    html.H3([
                        html.I(className="fas fa-list", style={'margin-right': '10px', 'color': '#3498db'}),
                        "🚨 Active Security Alerts"
                    ]),
                    html.Div(id="alerts-table")
                ], className="alerts-section")
            ], className="dashboard-container")
        ])
    
    def _create_beautiful_stat_card(self, title: str, id_suffix: str, emoji: str, color: str):
        """Create a beautiful statistics card with emoji and gradient"""
        return html.Div([
            html.Div([
                html.Div([
                    html.Span(emoji, className="stat-icon", style={'font-size': '3em'}),
                ], style={'display': 'flex', 'align-items': 'center'}),
                html.Div([
                    html.H3("0", id=f"stat-{id_suffix}", style={'color': color}),
                    html.P(title, style={'color': '#7f8c8d'})
                ], className="stat-text")
            ], className="stat-content")
        ], className="stat-card", style={'--card-color': color})
    
    def _setup_callbacks(self):
        """Setup dashboard callbacks for interactivity"""
        
        @self.app.callback(
            [Output('stat-dataset-entries', 'children'),
             Output('stat-total-alerts', 'children'),
             Output('stat-critical-alerts', 'children'),
             Output('stat-high-alerts', 'children'),
             Output('stat-medium-alerts', 'children'),
             Output('stat-low-alerts', 'children'),
             Output('severity-chart', 'figure'),
             Output('timeline-chart', 'figure'),
             Output('alerts-table', 'children'),
             Output('last-update', 'children')],
            [Input('interval-component', 'n_intervals'),
             Input('refresh-btn', 'n_clicks'),
             Input('severity-filter', 'value'),
             Input('status-filter', 'value')],
            [State('time-filter', 'value')]
        )
        def update_dashboard(n_intervals, refresh_clicks, severity_filter, status_filter, time_filter):
            # Generate dynamic data based on severity filter
            import random
            
            # Mock statistics with dataset info
            dataset_entries = 150  # Total entries from our datasets
            
            # Adjust counts based on filter
            if severity_filter == "CRITICAL":
                critical_count = random.randint(8, 15)
                high_count = 0
                medium_count = 0
                low_count = 0
                total_alerts = critical_count
            elif severity_filter == "HIGH":
                critical_count = 0
                high_count = random.randint(15, 25)
                medium_count = 0
                low_count = 0
                total_alerts = high_count
            elif severity_filter == "MEDIUM":
                critical_count = 0
                high_count = 0
                medium_count = random.randint(20, 35)
                low_count = 0
                total_alerts = medium_count
            elif severity_filter == "LOW":
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = random.randint(10, 20)
                total_alerts = low_count
            else:  # ALL
                critical_count = random.randint(2, 8)
                high_count = random.randint(8, 15)
                medium_count = random.randint(15, 25)
                low_count = random.randint(5, 12)
                total_alerts = critical_count + high_count + medium_count + low_count
            
            # Create beautiful charts with filter context
            severity_chart = self._create_beautiful_severity_chart(severity_filter, critical_count, high_count, medium_count, low_count)
            timeline_chart = self._create_beautiful_timeline_chart()
            
            # Create beautiful alerts table with severity filter
            alerts_table = self._create_beautiful_alerts_table(severity_filter or "ALL")
            
            # Last update timestamp
            last_update = f"🕒 Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            return (
                str(dataset_entries), str(total_alerts), str(critical_count), str(high_count), 
                str(medium_count), str(low_count),
                severity_chart, timeline_chart, alerts_table, last_update
            )
    
    def _create_beautiful_severity_chart(self, severity_filter="ALL", critical_count=0, high_count=0, medium_count=0, low_count=0):
        """Create a beautiful severity distribution chart"""
        import random
        
        # Use actual filtered data
        data = {
            'Critical': critical_count,
            'High': high_count,
            'Medium': medium_count,
            'Low': low_count
        }
        
        colors = ['#c0392b', '#e67e22', '#f39c12', '#27ae60']
        
        fig = go.Figure(data=[go.Pie(
            labels=list(data.keys()),
            values=list(data.values()),
            marker_colors=colors,
            textinfo='label+percent+value',
            textposition='inside',
            hole=0.4
        )])
        
        # Dynamic title based on filter
        if severity_filter and severity_filter != "ALL":
            chart_title = f"🎯 {severity_filter} Alerts Distribution"
        else:
            chart_title = "🎯 Alert Severity Distribution"
        
        fig.update_layout(
            title={
                'text': chart_title,
                'font': {'size': 12, 'color': '#2c3e50', 'family': 'Inter'},
                'x': 0.5
            },
            showlegend=True,
            height=235,
            margin=dict(t=40, b=13, l=13, r=13),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig
    
    def _create_beautiful_timeline_chart(self):
        """Create a beautiful timeline chart"""
        import random
        from datetime import datetime, timedelta
        
        # Generate mock timeline data
        hours = [(datetime.now() - timedelta(hours=i)).strftime('%H:%M') for i in range(24, 0, -1)]
        critical_data = [random.randint(0, 5) for _ in range(24)]
        high_data = [random.randint(2, 10) for _ in range(24)]
        medium_data = [random.randint(5, 15) for _ in range(24)]
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=hours, y=critical_data,
            mode='lines+markers',
            name='🔥 Critical',
            line=dict(color='#c0392b', width=3),
            marker=dict(size=8, color='#c0392b')
        ))
        
        fig.add_trace(go.Scatter(
            x=hours, y=high_data,
            mode='lines+markers',
            name='⚠️ High',
            line=dict(color='#e67e22', width=3),
            marker=dict(size=8, color='#e67e22')
        ))
        
        fig.add_trace(go.Scatter(
            x=hours, y=medium_data,
            mode='lines+markers',
            name='📊 Medium',
            line=dict(color='#f39c12', width=3),
            marker=dict(size=8, color='#f39c12')
        ))
        
        fig.update_layout(
            title={
                'text': "📈 24-Hour Alert Timeline",
                'font': {'size': 12, 'color': '#2c3e50', 'family': 'Inter'},
                'x': 0.5
            },
            xaxis_title="⏰ Time",
            yaxis_title="📊 Alert Count",
            height=235,
            margin=dict(t=40, b=33, l=33, r=13),
            showlegend=True,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(gridcolor='rgba(0,0,0,0.1)'),
            yaxis=dict(gridcolor='rgba(0,0,0,0.1)')
        )
        
        return fig
    
    def _create_beautiful_alerts_table(self, severity_filter="ALL"):
        """Create a beautiful alerts table with dynamic filtering"""
        import random
        from datetime import datetime, timedelta
        
        # Dynamic status options based on severity
        def get_dynamic_status(severity_level):
            if severity_level == "CRITICAL":
                statuses = ['🚨 ACTIVE', '🔍 INVESTIGATING', '🆕 NEW', '⚡ URGENT']
            elif severity_level == "HIGH":
                statuses = ['🔍 INVESTIGATING', '🆕 NEW', '👀 MONITORING', '📋 ASSIGNED']
            elif severity_level == "MEDIUM":
                statuses = ['👀 MONITORING', '📋 PENDING', '🔍 INVESTIGATING', '✅ RESOLVED']
            else:  # LOW
                statuses = ['📋 PENDING', '👀 MONITORING', '✅ RESOLVED', '⏳ SCHEDULED']
            return random.choice(statuses)
        
        # Generate dynamic alert data
        all_alerts = []
        
        # Critical alerts with dynamic status
        critical_alerts = [
            {'ID': '🆔 CRT001', 'Title': '🚨 Advanced Persistent Threat Detected', 'Severity': '🔥 CRITICAL', 'Status': get_dynamic_status("CRITICAL"), 'Source': '🛡️ EDR System', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 30))).strftime('%H:%M:%S')},
            {'ID': '🆔 CRT002', 'Title': '🚨 Ransomware Activity Detected', 'Severity': '🔥 CRITICAL', 'Status': get_dynamic_status("CRITICAL"), 'Source': '💻 Endpoint', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 30))).strftime('%H:%M:%S')},
            {'ID': '🆔 CRT003', 'Title': '🚨 Data Exfiltration Attempt', 'Severity': '🔥 CRITICAL', 'Status': get_dynamic_status("CRITICAL"), 'Source': '🌐 Network Monitor', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 30))).strftime('%H:%M:%S')},
            {'ID': '🆔 CRT004', 'Title': '🚨 Privilege Escalation Detected', 'Severity': '🔥 CRITICAL', 'Status': get_dynamic_status("CRITICAL"), 'Source': '🔐 Auth System', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 30))).strftime('%H:%M:%S')},
        ]
        
        # High alerts with dynamic status
        high_alerts = [
            {'ID': '🆔 HGH001', 'Title': '⚠️ Multiple Failed Login Attempts', 'Severity': '⚠️ HIGH', 'Status': get_dynamic_status("HIGH"), 'Source': '🔐 Auth System', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S')},
            {'ID': '🆔 HGH002', 'Title': '⚠️ Suspicious PowerShell Activity', 'Severity': '⚠️ HIGH', 'Status': get_dynamic_status("HIGH"), 'Source': '💻 Windows Event', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S')},
            {'ID': '🆔 HGH003', 'Title': '⚠️ Malware Signature Match', 'Severity': '⚠️ HIGH', 'Status': get_dynamic_status("HIGH"), 'Source': '🦠 Antivirus', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S')},
            {'ID': '🆔 HGH004', 'Title': '⚠️ Suspicious Network Connection', 'Severity': '⚠️ HIGH', 'Status': get_dynamic_status("HIGH"), 'Source': '🌐 Firewall', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S')},
            {'ID': '🆔 HGH005', 'Title': '⚠️ Unauthorized File Access', 'Severity': '⚠️ HIGH', 'Status': get_dynamic_status("HIGH"), 'Source': '📁 File Monitor', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%H:%M:%S')},
        ]
        
        # Medium alerts with dynamic status
        medium_alerts = [
            {'ID': '🆔 MED001', 'Title': '📊 Unusual Network Traffic Pattern', 'Severity': '📊 MEDIUM', 'Status': get_dynamic_status("MEDIUM"), 'Source': '🔗 Firewall', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime('%H:%M:%S')},
            {'ID': '🆔 MED002', 'Title': '📊 Port Scan Detected', 'Severity': '📊 MEDIUM', 'Status': get_dynamic_status("MEDIUM"), 'Source': '🌐 IDS', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime('%H:%M:%S')},
            {'ID': '🆔 MED003', 'Title': '📊 Certificate Expiry Warning', 'Severity': '📊 MEDIUM', 'Status': get_dynamic_status("MEDIUM"), 'Source': '🔒 SSL Monitor', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime('%H:%M:%S')},
            {'ID': '🆔 MED004', 'Title': '📊 Bandwidth Usage Spike', 'Severity': '📊 MEDIUM', 'Status': get_dynamic_status("MEDIUM"), 'Source': '📈 Network Monitor', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 120))).strftime('%H:%M:%S')},
        ]
        
        # Low alerts with dynamic status
        low_alerts = [
            {'ID': '🆔 LOW001', 'Title': '💡 System Update Available', 'Severity': '💡 LOW', 'Status': get_dynamic_status("LOW"), 'Source': '🖥️ System', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 240))).strftime('%H:%M:%S')},
            {'ID': '🆔 LOW002', 'Title': '💡 Disk Space Warning', 'Severity': '💡 LOW', 'Status': get_dynamic_status("LOW"), 'Source': '💾 Storage', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 240))).strftime('%H:%M:%S')},
            {'ID': '🆔 LOW003', 'Title': '💡 Log Rotation Scheduled', 'Severity': '💡 LOW', 'Status': get_dynamic_status("LOW"), 'Source': '📝 Log Manager', 'Time': (datetime.now() - timedelta(minutes=random.randint(1, 240))).strftime('%H:%M:%S')},
        ]
        
        # Filter alerts based on severity
        if severity_filter == "CRITICAL":
            filtered_alerts = random.sample(critical_alerts, min(len(critical_alerts), random.randint(2, 3)))
        elif severity_filter == "HIGH":
            filtered_alerts = random.sample(high_alerts, min(len(high_alerts), random.randint(3, 5)))
        elif severity_filter == "MEDIUM":
            filtered_alerts = random.sample(medium_alerts, min(len(medium_alerts), random.randint(2, 4)))
        elif severity_filter == "LOW":
            filtered_alerts = random.sample(low_alerts, min(len(low_alerts), random.randint(1, 3)))
        else:  # ALL
            all_alerts = critical_alerts[:2] + high_alerts[:3] + medium_alerts[:2] + low_alerts[:1]
            filtered_alerts = random.sample(all_alerts, min(len(all_alerts), 8))
        
        # Randomize IDs for uniqueness
        for alert in filtered_alerts:
            base_id = alert['ID'][:7]  # Keep prefix like "🆔 CRT"
            alert['ID'] = f"{base_id}{random.randint(100, 999):03d}"
        
        return dash_table.DataTable(
            data=filtered_alerts,
            columns=[
                {"name": "🆔 Alert ID", "id": "ID"},
                {"name": "📋 Title", "id": "Title"},
                {"name": "🎯 Severity", "id": "Severity"},
                {"name": "📊 Status", "id": "Status"},
                {"name": "📡 Source", "id": "Source"},
                {"name": "⏰ Time", "id": "Time"}
            ],
            style_cell={
                'textAlign': 'left',
                'padding': '10px',
                'fontFamily': 'Inter, sans-serif',
                'fontSize': '12px',
                'border': '1px solid #e9ecef'
            },
            style_header={
                'backgroundColor': '#3498db',
                'color': 'white',
                'fontWeight': '600',
                'textAlign': 'center'
            },
            style_data_conditional=[
                {
                    'if': {'filter_query': '{Severity} contains CRITICAL'},
                    'backgroundColor': '#fadbd8',
                    'color': '#c0392b',
                    'fontWeight': 'bold'
                },
                {
                    'if': {'filter_query': '{Severity} contains HIGH'},
                    'backgroundColor': '#fdeaa7',
                    'color': '#e67e22',
                    'fontWeight': 'bold'
                },
                {
                    'if': {'filter_query': '{Status} contains NEW'},
                    'fontWeight': 'bold',
                    'backgroundColor': '#e8f5e8'
                }
            ],
            page_size=10,
            sort_action="native",
            filter_action="native",
            style_table={'borderRadius': '10px', 'overflow': 'hidden'}
        )
    
    def update_stats(self, stats_data):
        """Update dashboard statistics (placeholder for compatibility)"""
        # This method is called by the processing pipeline
        # In a real implementation, this would update live stats
        pass
    
    def run(self, host="0.0.0.0", port=8080, debug=False):
        """Run the beautiful dashboard"""
        # Show the correct URL for users to access
        access_url = "localhost" if host == "0.0.0.0" else host
        print(f"🚀 Starting Beautiful SIEM-Fusion Dashboard")
        print(f"📊 Dashboard URL: http://{access_url}:{port}")
        print(f"🌐 Server binding: {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)
