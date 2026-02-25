#!/usr/bin/env python3
"""
BrunswickPot TUI - Terminal User Interface for honeypot monitoring
Real-time dashboard with activity logs, statistics, and attacker details
"""

import os
import sys
from datetime import datetime, timezone, timedelta
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Footer, Static, DataTable, Label, Button
from textual.reactive import reactive
from textual import work
from rich.text import Text
from rich.table import Table as RichTable
from rich.panel import Panel
from rich.layout import Layout
from sqlalchemy import create_engine, func, desc
from sqlalchemy.orm import sessionmaker
import yaml

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.database.models import HoneypotEvent, Base


class StatsWidget(Static):
    """Widget to display statistics"""

    total_events = reactive(0)
    recent_events = reactive(0)
    unique_ips = reactive(0)
    credentials = reactive(0)

    def render(self) -> RichTable:
        """Render statistics table"""
        table = RichTable.grid(padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column(style="bold yellow", justify="right")

        table.add_row("📊 Total Events:", str(self.total_events))
        table.add_row("🔥 Recent (24h):", str(self.recent_events))
        table.add_row("🌐 Unique IPs:", str(self.unique_ips))
        table.add_row("🔑 Credentials:", str(self.credentials))

        return table


class SeverityWidget(Static):
    """Widget to display severity breakdown"""

    critical = reactive(0)
    high = reactive(0)
    medium = reactive(0)
    low = reactive(0)

    def render(self) -> RichTable:
        """Render severity breakdown"""
        table = RichTable.grid(padding=(0, 2))
        table.add_column(style="bold")
        table.add_column(justify="right")

        if self.critical > 0:
            table.add_row("[red]🔴 Critical:[/red]", f"[red]{self.critical}[/red]")
        if self.high > 0:
            table.add_row("[orange1]🟠 High:[/orange1]", f"[orange1]{self.high}[/orange1]")
        if self.medium > 0:
            table.add_row("[yellow]🟡 Medium:[/yellow]", f"[yellow]{self.medium}[/yellow]")
        if self.low > 0:
            table.add_row("[green]🟢 Low:[/green]", f"[green]{self.low}[/green]")

        return table


class ServiceWidget(Static):
    """Widget to display service breakdown"""

    services = reactive({})

    def render(self) -> RichTable:
        """Render service breakdown"""
        table = RichTable.grid(padding=(0, 2))
        table.add_column(style="bold cyan")
        table.add_column(justify="right", style="bold yellow")

        service_icons = {
            'ssh': '🔐',
            'http': '🌐',
            'smb': '📁',
            'ldap': '📋'
        }

        for service, count in self.services.items():
            icon = service_icons.get(service, '⚡')
            table.add_row(f"{icon} {service.upper()}:", str(count))

        return table


class TopAttackersWidget(Static):
    """Widget to display top attackers"""

    attackers = reactive([])

    def render(self) -> RichTable:
        """Render top attackers table"""
        table = RichTable(title="🎯 Top Attackers", box=None, show_header=True)
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Country", style="green")
        table.add_column("Risk", style="red")

        for attacker in self.attackers[:10]:
            ip = attacker.get('ip', 'unknown')
            count = str(attacker.get('count', 0))
            country = attacker.get('country', '??')
            risk = attacker.get('risk_level', 'unknown')

            # Color code risk level
            risk_color = {
                'critical': 'red',
                'high': 'orange1',
                'medium': 'yellow',
                'low': 'green'
            }.get(risk, 'white')

            risk_display = f"[{risk_color}]{risk}[/{risk_color}]"

            table.add_row(ip, count, country, risk_display)

        return table


class EventsTable(Static):
    """Widget to display recent events"""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.events = []

    def update_events(self, events):
        """Update the events list"""
        self.events = events
        self.refresh()

    def render(self) -> RichTable:
        """Render events table"""
        table = RichTable(
            title="📝 Recent Events",
            box=None,
            show_header=True,
            header_style="bold magenta"
        )

        table.add_column("Time", style="cyan", width=10)
        table.add_column("Service", style="blue", width=8)
        table.add_column("IP", style="yellow", width=15)
        table.add_column("Country", style="green", width=8)
        table.add_column("Event", style="white", width=20)
        table.add_column("User", style="magenta", width=15)
        table.add_column("Severity", width=10)

        for event in self.events[:20]:
            timestamp = event.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    time_str = dt.strftime('%H:%M:%S')
                except:
                    time_str = timestamp[:8]
            else:
                time_str = '--:--:--'

            service = event.get('service', 'unknown')
            ip = event.get('source_ip', 'unknown')
            country = event.get('country', '??') or '??'
            event_type = event.get('event_type', 'unknown')
            username = event.get('username', '-') or '-'
            severity = event.get('severity', 'unknown')

            # Color code severity
            severity_styles = {
                'critical': 'red',
                'high': 'orange1',
                'medium': 'yellow',
                'low': 'green'
            }
            severity_color = severity_styles.get(severity, 'white')
            severity_display = f"[{severity_color}]{severity}[/{severity_color}]"

            # Truncate long fields
            if len(event_type) > 20:
                event_type = event_type[:17] + '...'
            if len(username) > 15:
                username = username[:12] + '...'

            table.add_row(
                time_str,
                service,
                ip,
                country,
                event_type,
                username,
                severity_display
            )

        return table


class HoneypotTUI(App):
    """BrunswickPot Terminal User Interface"""

    CSS = """
    Screen {
        background: $surface;
    }

    #main-container {
        height: 100%;
        layout: vertical;
    }

    #top-section {
        height: auto;
        layout: horizontal;
    }

    #stats-panel {
        width: 1fr;
        height: auto;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }

    #severity-panel {
        width: 1fr;
        height: auto;
        border: solid $warning;
        padding: 1;
        margin: 1;
    }

    #service-panel {
        width: 1fr;
        height: auto;
        border: solid $success;
        padding: 1;
        margin: 1;
    }

    #attackers-panel {
        height: auto;
        border: solid $error;
        padding: 1;
        margin: 1;
    }

    #events-panel {
        height: 1fr;
        border: solid $accent;
        padding: 1;
        margin: 1;
    }

    Header {
        background: $primary-darken-2;
    }

    Footer {
        background: $primary-darken-2;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "refresh", "Refresh"),
        ("c", "clear_filters", "Clear Filters"),
    ]

    def __init__(self, config_path='honeypot_config.yaml'):
        super().__init__()
        self.config_path = config_path
        self.load_database()

    def load_database(self):
        """Load database configuration"""
        with open(self.config_path, 'r') as f:
            config = yaml.safe_load(f)

        db_config = config.get('database', {})
        if db_config.get('type') == 'sqlite':
            db_path = db_config.get('sqlite_path', './data/honeypot_events.db')
            db_url = f'sqlite:///{db_path}'
        elif db_config.get('type') == 'postgresql':
            pg = db_config.get('postgresql', {})
            db_url = f"postgresql://{pg['username']}:{pg['password']}@{pg['host']}:{pg['port']}/{pg['database']}"
        else:
            db_url = 'sqlite:///./data/honeypot_events.db'

        self.engine = create_engine(db_url)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def compose(self) -> ComposeResult:
        """Create child widgets"""
        yield Header(show_clock=True)

        with Container(id="main-container"):
            with Horizontal(id="top-section"):
                with Container(id="stats-panel"):
                    yield Static("📊 [bold cyan]Statistics[/bold cyan]")
                    yield StatsWidget(id="stats")

                with Container(id="severity-panel"):
                    yield Static("⚠️  [bold yellow]Severity[/bold yellow]")
                    yield SeverityWidget(id="severity")

                with Container(id="service-panel"):
                    yield Static("🛠️  [bold green]Services[/bold green]")
                    yield ServiceWidget(id="services")

            with Container(id="attackers-panel"):
                yield TopAttackersWidget(id="attackers")

            with Container(id="events-panel"):
                yield EventsTable(id="events")

        yield Footer()

    def on_mount(self) -> None:
        """Start the update loop when mounted"""
        self.set_interval(5, self.update_data)
        self.update_data()

    @work(exclusive=True, thread=True)
    def update_data(self):
        """Update all dashboard data"""
        session = self.Session()
        try:
            # Get statistics
            time_window = datetime.now(timezone.utc) - timedelta(hours=24)

            total_events = session.query(func.count(HoneypotEvent.id)).scalar() or 0
            recent_events = session.query(func.count(HoneypotEvent.id)).filter(
                HoneypotEvent.timestamp >= time_window
            ).scalar() or 0
            unique_ips = session.query(func.count(func.distinct(HoneypotEvent.source_ip))).scalar() or 0
            credentials = session.query(func.count(HoneypotEvent.id)).filter(
                HoneypotEvent.credential_captured == 1
            ).scalar() or 0

            # Update stats widget
            stats_widget = self.query_one("#stats", StatsWidget)
            stats_widget.total_events = total_events
            stats_widget.recent_events = recent_events
            stats_widget.unique_ips = unique_ips
            stats_widget.credentials = credentials

            # Get severity breakdown
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for severity, count in session.query(
                HoneypotEvent.severity, func.count(HoneypotEvent.id)
            ).filter(HoneypotEvent.timestamp >= time_window).group_by(HoneypotEvent.severity).all():
                severity_counts[severity] = count

            severity_widget = self.query_one("#severity", SeverityWidget)
            severity_widget.critical = severity_counts.get('critical', 0)
            severity_widget.high = severity_counts.get('high', 0)
            severity_widget.medium = severity_counts.get('medium', 0)
            severity_widget.low = severity_counts.get('low', 0)

            # Get service breakdown
            service_counts = {}
            for service, count in session.query(
                HoneypotEvent.service, func.count(HoneypotEvent.id)
            ).filter(HoneypotEvent.timestamp >= time_window).group_by(HoneypotEvent.service).all():
                service_counts[service] = count

            service_widget = self.query_one("#services", ServiceWidget)
            service_widget.services = service_counts

            # Get top attackers
            results = session.query(
                HoneypotEvent.source_ip,
                func.count(HoneypotEvent.id).label('count')
            ).filter(
                HoneypotEvent.timestamp >= time_window
            ).group_by(
                HoneypotEvent.source_ip
            ).order_by(
                desc('count')
            ).limit(10).all()

            attackers = []
            for ip, count in results:
                event = session.query(HoneypotEvent).filter(
                    HoneypotEvent.source_ip == ip
                ).order_by(desc(HoneypotEvent.timestamp)).first()

                enrichment = event.enrichment_data if event and event.enrichment_data else {}
                geoip = enrichment.get('geoip', {})
                reputation = enrichment.get('reputation', {})

                attackers.append({
                    'ip': ip,
                    'count': count,
                    'country': geoip.get('country'),
                    'risk_level': reputation.get('risk_level')
                })

            attackers_widget = self.query_one("#attackers", TopAttackersWidget)
            attackers_widget.attackers = attackers

            # Get recent events
            events = session.query(HoneypotEvent).order_by(
                desc(HoneypotEvent.timestamp)
            ).limit(50).all()

            events_data = []
            for event in events:
                enrichment = event.enrichment_data or {}
                geoip = enrichment.get('geoip', {})

                events_data.append({
                    'timestamp': event.timestamp.isoformat() if event.timestamp else None,
                    'service': event.service,
                    'event_type': event.event_type,
                    'severity': event.severity,
                    'source_ip': event.source_ip,
                    'username': event.username,
                    'country': geoip.get('country')
                })

            events_widget = self.query_one("#events", EventsTable)
            events_widget.update_events(events_data)

        finally:
            session.close()

    def action_refresh(self) -> None:
        """Manually refresh data"""
        self.update_data()

    def action_clear_filters(self) -> None:
        """Clear any filters (placeholder for future functionality)"""
        pass


def main():
    """Run the TUI"""
    import argparse
    parser = argparse.ArgumentParser(description='BrunswickPot Terminal Dashboard')
    parser.add_argument('--config', default='honeypot_config.yaml', help='Path to config file')
    args = parser.parse_args()

    app = HoneypotTUI(config_path=args.config)
    app.run()


if __name__ == '__main__':
    main()
