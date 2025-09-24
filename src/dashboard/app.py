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

class SIEMDashboard:
    """SOC Dashboard for SIEM-Fusion alert presentation"""
    
    def __init__(self):
        self.app = dash.Dash(__name__, external_stylesheets=[
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
            'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap'
        ])
        
        # Add custom CSS
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
                        backdrop-filter: blur(20px);
                        border-radius: 20px;
                        margin: 20px;
                        padding: 30px;
                        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
                        border: 1px solid rgba(255, 255, 255, 0.2);
                    }
                    
                    .header {
                        background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                        color: white;
                        padding: 25px 30px;
                        border-radius: 15px;
                        margin-bottom: 30px;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        box-shadow: 0 10px 30px rgba(44, 62, 80, 0.3);
                    }
                    
                    .header-title {
                        font-size: 2.2em;
                        font-weight: 700;
                        margin: 0;
                        display: flex;
                        align-items: center;
                        background: linear-gradient(45deg, #3498db, #2ecc71);
                        -webkit-background-clip: text;
                        -webkit-text-fill-color: transparent;
                        background-clip: text;
                    }
                    
                    .header-controls {
                        display: flex;
                        align-items: center;
                        gap: 20px;
                    }
                    
                    .refresh-btn {
                        background: linear-gradient(135deg, #3498db, #2980b9);
                        border: none;
                        color: white;
                        padding: 12px 24px;
                        border-radius: 25px;
                        cursor: pointer;
                        font-weight: 600;
                        transition: all 0.3s ease;
                        box-shadow: 0 5px 15px rgba(52, 152, 219, 0.3);
                    }
                    
                    .refresh-btn:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 25px rgba(52, 152, 219, 0.4);
                    }
                    
                    .stats-row {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 20px;
                        margin-bottom: 30px;
                    }
                    
                    .stat-card {
                        background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
                        border-radius: 15px;
                        padding: 25px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                        transition: all 0.3s ease;
                        position: relative;
                        overflow: hidden;
                    }
                    
                    .stat-card:hover {
                        transform: translateY(-5px);
                        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.12);
                    }
                    
                    .stat-card::before {
                        content: '';
                        position: absolute;
                        top: 0;
                        left: 0;
                        right: 0;
                        height: 4px;
                        background: var(--card-color, #3498db);
                    }
                    
                    .stat-content {
                        display: flex;
                        align-items: center;
                        gap: 20px;
                    }
                    
                    .stat-icon {
                        font-size: 2.5em;
                        opacity: 0.8;
                    }
                    
                    .stat-text h3 {
                        font-size: 2.5em;
                        font-weight: 700;
                        margin: 0;
                        color: #2c3e50;
                    }
                    
                    .stat-text p {
                        font-size: 0.9em;
                        color: #7f8c8d;
                        margin: 5px 0 0 0;
                        font-weight: 500;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                    }
                    
                    .charts-row {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 30px;
                        margin-bottom: 30px;
                    }
                    
                    .chart-container {
                        background: white;
                        border-radius: 15px;
                        padding: 20px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                    }
                    
                    .filters-row {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 20px;
                        margin-bottom: 30px;
                        background: white;
                        padding: 25px;
                        border-radius: 15px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
                    }
                    
                    .filter-group label {
                        font-weight: 600;
                        color: #2c3e50;
                        margin-bottom: 8px;
                        display: block;
                    }
                    
                    .alerts-section {
                        background: white;
                        border-radius: 15px;
                        padding: 30px;
                        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
                        border: 1px solid rgba(255, 255, 255, 0.8);
                    }
                    
                    .alerts-section h3 {
                        color: #2c3e50;
                        font-weight: 700;
                        margin-bottom: 20px;
                        font-size: 1.5em;
                    }
                    
                    .last-update {
                        color: rgba(255, 255, 255, 0.8);
                        font-size: 0.9em;
                        font-weight: 500;
                    }
                    
                    /* Responsive design */
                    @media (max-width: 768px) {
                        .charts-row {
                            grid-template-columns: 1fr;
                        }
                        
                        .header {
                            flex-direction: column;
                            gap: 15px;
                            text-align: center;
                        }
                        
                        .header-title {
                            font-size: 1.8em;
                        }
                    }
                    
                    /* Animation for loading */
                    @keyframes pulse {
                        0% { opacity: 1; }
                        50% { opacity: 0.5; }
                        100% { opacity: 1; }
                    }
                    
                    .loading {
                        animation: pulse 2s infinite;
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
        self.refresh_interval = config.dashboard_config.get('refresh_interval', 10) * 1000  # Convert to ms
        self.max_alerts_display = config.dashboard_config.get('max_alerts_display', 50)
        
        # Mock data storage (in production, this would connect to a database)
        self.alerts: List[Alert] = []
        self.stats = ProcessingStats()
        
        self._setup_layout()
        self._setup_callbacks()
    
    def _setup_layout(self):
        """Setup the beautiful dashboard layout"""
        self.app.layout = html.Div([
            html.Div([
                # Header
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
                
                # Statistics row with beautiful cards
                html.Div([
                    self._create_beautiful_stat_card("Total Alerts", "total-alerts", "fas fa-exclamation-triangle", "#e74c3c", "🚨"),
                    self._create_beautiful_stat_card("Critical", "critical-alerts", "fas fa-fire", "#c0392b", "🔥"),
                    self._create_beautiful_stat_card("High", "high-alerts", "fas fa-exclamation", "#e67e22", "⚠️"),
                    self._create_beautiful_stat_card("Medium", "medium-alerts", "fas fa-info", "#f39c12", "📊"),
                    self._create_beautiful_stat_card("Low", "low-alerts", "fas fa-check", "#27ae60", "✅")
                ], className="stats-row"),
                # Statistics row
                html.Div([
                    self._create_stat_card("Total Alerts", "total-alerts", "fas fa-exclamation-triangle", "#e74c3c"),
                    self._create_stat_card("Critical", "critical-alerts", "fas fa-fire", "#c0392b"),
                    self._create_stat_card("High", "high-alerts", "fas fa-exclamation", "#e67e22"),
                    self._create_stat_card("Medium", "medium-alerts", "fas fa-info", "#f39c12"),
                    self._create_stat_card("Low", "low-alerts", "fas fa-check", "#27ae60")
                ], className="stats-row"),
                
                # Charts row
                html.Div([
                    html.Div([
                        dcc.Graph(id="severity-chart")
                    ], className="chart-container"),
                    html.Div([
                        dcc.Graph(id="timeline-chart")
                    ], className="chart-container")
                ], className="charts-row"),
                
                # Filters and controls
                html.Div([
                    html.Div([
                        html.Label("Filter by Severity:"),
                        dcc.Dropdown(
                            id="severity-filter",
                            options=[
                                {'label': 'All', 'value': 'all'},
                                {'label': 'Critical', 'value': 'critical'},
                                {'label': 'High', 'value': 'high'},
                                {'label': 'Medium', 'value': 'medium'},
                                {'label': 'Low', 'value': 'low'}
                            ],
                            value='all',
                            className="filter-dropdown"
                        )
                    ], className="filter-group"),
                    html.Div([
                        html.Label("Filter by Status:"),
                        dcc.Dropdown(
                            id="status-filter",
                            options=[
                                {'label': 'All', 'value': 'all'},
                                {'label': 'New', 'value': 'new'},
                                {'label': 'Investigating', 'value': 'investigating'},
                                {'label': 'Resolved', 'value': 'resolved'}
                            ],
                            value='all',
                            className="filter-dropdown"
                        )
                    ], className="filter-group"),
                    html.Div([
                        html.Label("Time Range:"),
                        dcc.Dropdown(
                            id="time-filter",
                            options=[
                                {'label': 'Last Hour', 'value': '1h'},
                                {'label': 'Last 6 Hours', 'value': '6h'},
                                {'label': 'Last 24 Hours', 'value': '24h'},
                                {'label': 'Last 7 Days', 'value': '7d'}
                            ],
                            value='24h',
                            className="filter-dropdown"
                        )
                    ], className="filter-group")
                ], className="filters-row"),
                
                # Alerts table
                html.Div([
                    html.H3("Active Alerts"),
                    html.Div(id="alerts-table")
                ], className="alerts-section")
            ], className="main-content")
        ])
    
    def _create_stat_card(self, title: str, id_suffix: str, icon: str, color: str):
        """Create a statistics card"""
        return html.Div([
            html.Div([
                html.I(className=icon, style={'color': color, 'font-size': '2em'}),
                html.Div([
                    html.H3("0", id=f"stat-{id_suffix}"),
                    html.P(title)
                ], className="stat-text")
            ], className="stat-content")
        ], className="stat-card")
    
    def _setup_callbacks(self):
        """Setup dashboard callbacks"""
        
        @self.app.callback(
            [Output('stat-total-alerts', 'children'),
             Output('stat-critical-alerts', 'children'),
             Output('stat-high-alerts', 'children'),
             Output('stat-medium-alerts', 'children'),
             Output('stat-low-alerts', 'children'),
             Output('severity-chart', 'figure'),
             Output('timeline-chart', 'figure'),
             Output('alerts-table', 'children'),
             Output('last-update', 'children')],
            [Input('interval-component', 'n_intervals'),
             Input('refresh-btn', 'n_clicks')],
            [State('severity-filter', 'value'),
             State('status-filter', 'value'),
             State('time-filter', 'value')]
        )
        def update_dashboard(n_intervals, refresh_clicks, severity_filter, status_filter, time_filter):
            # Filter alerts based on selected criteria
            filtered_alerts = self._filter_alerts(severity_filter, status_filter, time_filter)
            
            # Calculate statistics
            total_alerts = len(filtered_alerts)
            critical_count = len([a for a in filtered_alerts if a.severity == SeverityLevel.CRITICAL])
            high_count = len([a for a in filtered_alerts if a.severity == SeverityLevel.HIGH])
            medium_count = len([a for a in filtered_alerts if a.severity == SeverityLevel.MEDIUM])
            low_count = len([a for a in filtered_alerts if a.severity == SeverityLevel.LOW])
            
            # Create charts
            severity_chart = self._create_severity_chart(filtered_alerts)
            timeline_chart = self._create_timeline_chart(filtered_alerts)
            
            # Create alerts table
            alerts_table = self._create_alerts_table(filtered_alerts)
            
            # Last update timestamp
            last_update = f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            return (
                str(total_alerts), str(critical_count), str(high_count), 
                str(medium_count), str(low_count),
                severity_chart, timeline_chart, alerts_table, last_update
            )
    
    def _filter_alerts(self, severity_filter: str, status_filter: str, time_filter: str) -> List[Alert]:
        """Filter alerts based on selected criteria"""
        filtered = self.alerts.copy()
        
        # Filter by severity
        if severity_filter != 'all':
            filtered = [a for a in filtered if a.severity.value == severity_filter]
        
        # Filter by status
        if status_filter != 'all':
            filtered = [a for a in filtered if a.status.value == status_filter]
        
        # Filter by time range
        now = datetime.now()
        if time_filter == '1h':
            cutoff = now - timedelta(hours=1)
        elif time_filter == '6h':
            cutoff = now - timedelta(hours=6)
        elif time_filter == '24h':
            cutoff = now - timedelta(hours=24)
        elif time_filter == '7d':
            cutoff = now - timedelta(days=7)
        else:
            cutoff = now - timedelta(hours=24)  # Default
        
        filtered = [a for a in filtered if a.created_at > cutoff]
        
        return filtered[:self.max_alerts_display]
    
    def _create_severity_chart(self, alerts: List[Alert]):
        """Create severity distribution pie chart"""
        if not alerts:
            return go.Figure().add_annotation(
                text="No alerts to display",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font_size=16
            )
        
        severity_counts = {}
        for alert in alerts:
            severity = alert.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        colors = {
            'critical': '#c0392b',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#27ae60'
        }
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker_colors=[colors.get(k, '#95a5a6') for k in severity_counts.keys()],
            textinfo='label+percent',
            textposition='inside'
        )])
        
        fig.update_layout(
            title="Alert Severity Distribution",
            showlegend=True,
            height=300,
            margin=dict(t=50, b=20, l=20, r=20)
        )
        
        return fig
    
    def _create_timeline_chart(self, alerts: List[Alert]):
        """Create timeline chart of alerts"""
        if not alerts:
            return go.Figure().add_annotation(
                text="No alerts to display",
                xref="paper", yref="paper",
                x=0.5, y=0.5, xanchor='center', yanchor='middle',
                showarrow=False, font_size=16
            )
        
        # Group alerts by hour
        df = pd.DataFrame([{
            'timestamp': alert.created_at,
            'severity': alert.severity.value,
            'count': 1
        } for alert in alerts])
        
        df['hour'] = df['timestamp'].dt.floor('H')
        hourly_counts = df.groupby(['hour', 'severity']).count().reset_index()
        
        colors = {
            'critical': '#c0392b',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#27ae60'
        }
        
        fig = go.Figure()
        
        for severity in ['critical', 'high', 'medium', 'low']:
            severity_data = hourly_counts[hourly_counts['severity'] == severity]
            if not severity_data.empty:
                fig.add_trace(go.Scatter(
                    x=severity_data['hour'],
                    y=severity_data['count'],
                    mode='lines+markers',
                    name=severity.title(),
                    line=dict(color=colors[severity]),
                    marker=dict(color=colors[severity])
                ))
        
        fig.update_layout(
            title="Alert Timeline",
            xaxis_title="Time",
            yaxis_title="Number of Alerts",
            height=300,
            margin=dict(t=50, b=50, l=50, r=20),
            showlegend=True
        )
        
        return fig
    
    def _create_alerts_table(self, alerts: List[Alert]):
        """Create alerts data table"""
        if not alerts:
            return html.Div("No alerts to display", className="no-alerts")
        
        # Prepare data for table
        table_data = []
        for alert in alerts:
            # Get key entities for display
            entities_summary = []
            if alert.entities.get('ips'):
                entities_summary.append(f"IPs: {', '.join(alert.entities['ips'][:2])}")
            if alert.entities.get('users'):
                entities_summary.append(f"Users: {', '.join(alert.entities['users'][:2])}")
            
            entities_str = "; ".join(entities_summary) if entities_summary else "N/A"
            
            table_data.append({
                'ID': alert.id[:8] + "...",
                'Title': alert.title,
                'Severity': alert.severity.value.upper(),
                'Status': alert.status.value.upper(),
                'Confidence': f"{alert.confidence:.2f}",
                'Entities': entities_str,
                'Created': alert.created_at.strftime('%Y-%m-%d %H:%M'),
                'Actions': "View | Investigate | Resolve"
            })
        
        # Define column styling
        columns = [
            {"name": "ID", "id": "ID", "width": "10%"},
            {"name": "Title", "id": "Title", "width": "25%"},
            {"name": "Severity", "id": "Severity", "width": "10%"},
            {"name": "Status", "id": "Status", "width": "10%"},
            {"name": "Confidence", "id": "Confidence", "width": "10%"},
            {"name": "Entities", "id": "Entities", "width": "20%"},
            {"name": "Created", "id": "Created", "width": "10%"},
            {"name": "Actions", "id": "Actions", "width": "15%"}
        ]
        
        return dash_table.DataTable(
            data=table_data,
            columns=columns,
            style_cell={
                'textAlign': 'left',
                'padding': '10px',
                'fontFamily': 'Arial, sans-serif',
                'fontSize': '14px'
            },
            style_header={
                'backgroundColor': '#34495e',
                'color': 'white',
                'fontWeight': 'bold'
            },
            style_data_conditional=[
                {
                    'if': {'filter_query': '{Severity} = CRITICAL'},
                    'backgroundColor': '#fadbd8',
                    'color': 'black',
                },
                {
                    'if': {'filter_query': '{Severity} = HIGH'},
                    'backgroundColor': '#fdeaa7',
                    'color': 'black',
                },
                {
                    'if': {'filter_query': '{Status} = NEW'},
                    'fontWeight': 'bold'
                }
            ],
            page_size=20,
            sort_action="native",
            filter_action="native"
        )
    
    def add_alert(self, alert: Alert):
        """Add a new alert to the dashboard"""
        self.alerts.append(alert)
        # Keep only recent alerts to prevent memory issues
        if len(self.alerts) > self.max_alerts_display * 2:
            self.alerts = self.alerts[-self.max_alerts_display:]
    
    def update_stats(self, stats: ProcessingStats):
        """Update processing statistics"""
        self.stats = stats
    
    def run(self, host: str = None, port: int = None, debug: bool = False):
        """Run the dashboard server"""
        host = host or config.dashboard_config.get('host', '0.0.0.0')
        port = port or config.dashboard_config.get('port', 8080)
        
        print(f"Starting SIEM-Fusion Dashboard on http://{host}:{port}")
        try:
            # Try new Dash method first
            self.app.run(host=host, port=port, debug=debug)
        except AttributeError:
            # Fallback to older method
            self.app.run_server(host=host, port=port, debug=debug)
