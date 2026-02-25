"""
MCP Server for Honeypot
Exposes honeypot data and threat intelligence via Model Context Protocol
Allows AI assistants like Claude to query attack data and provide analysis
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp import types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    print("Warning: mcp library not available. Install with: pip install mcp")

from honeypot.database.persistence import DatabaseManager
from honeypot.enrichment.enrichment_manager import EnrichmentManager
import yaml

logger = logging.getLogger(__name__)


class HoneypotMCPServer:
    """MCP Server for Honeypot data access"""

    def __init__(self, config_path: str = 'honeypot_config.yaml'):
        """
        Initialize MCP server

        Args:
            config_path: Path to honeypot configuration file
        """
        # Load configuration
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.mcp_config = self.config.get('mcp', {})
        self.honeypot_id = self.config.get('general', {}).get('honeypot_name', 'honeypot-01')

        # Initialize database manager
        db_config = self.config.get('database', {})
        self.db_manager = DatabaseManager(db_config) if db_config.get('enabled') else None

        # Initialize enrichment manager
        enrichment_config = self.config.get('enrichment', {})
        self.enrichment_manager = EnrichmentManager(enrichment_config) if enrichment_config.get('enabled') else None

        # Create MCP server
        self.server = Server("honeypot-mcp-server")

        # Register tools
        self._register_tools()

        logger.info("HoneypotMCPServer initialized")

    def _register_tools(self):
        """Register MCP tools"""

        @self.server.list_tools()
        async def list_tools() -> list[types.Tool]:
            """List available tools"""
            return [
                types.Tool(
                    name="query_recent_events",
                    description="Get recent honeypot events with optional filtering by service, severity, IP, or time range",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of events to return (default: 10)",
                                "default": 10
                            },
                            "service": {
                                "type": "string",
                                "description": "Filter by service (ssh, smb, http, ldap)",
                                "enum": ["ssh", "smb", "http", "ldap"]
                            },
                            "severity": {
                                "type": "string",
                                "description": "Filter by severity level",
                                "enum": ["low", "medium", "high", "critical"]
                            },
                            "hours": {
                                "type": "integer",
                                "description": "Get events from last N hours (default: 24)",
                                "default": 24
                            }
                        }
                    }
                ),
                types.Tool(
                    name="query_by_ip",
                    description="Get all events and threat intelligence profile for a specific IP address",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip": {
                                "type": "string",
                                "description": "IP address to query",
                                "required": True
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of events to return (default: 50)",
                                "default": 50
                            }
                        },
                        "required": ["ip"]
                    }
                ),
                types.Tool(
                    name="get_attack_statistics",
                    description="Get aggregate attack statistics and metrics",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "hours": {
                                "type": "integer",
                                "description": "Time window in hours (default: 24)",
                                "default": 24
                            }
                        }
                    }
                ),
                types.Tool(
                    name="search_events",
                    description="Search events by keywords or patterns",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "event_type": {
                                "type": "string",
                                "description": "Filter by event type (e.g., ssh_auth_attempt, http_post)"
                            },
                            "username": {
                                "type": "string",
                                "description": "Search for specific username attempts"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum results (default: 20)",
                                "default": 20
                            },
                            "hours": {
                                "type": "integer",
                                "description": "Search within last N hours (default: 24)",
                                "default": 24
                            }
                        }
                    }
                ),
                types.Tool(
                    name="get_threat_intelligence",
                    description="Get enriched threat intelligence for an IP address (GeoIP, ASN, reputation)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip": {
                                "type": "string",
                                "description": "IP address to lookup",
                                "required": True
                            }
                        },
                        "required": ["ip"]
                    }
                ),
                types.Tool(
                    name="get_top_attackers",
                    description="Get list of top attacking IP addresses",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Number of top attackers to return (default: 10)",
                                "default": 10
                            },
                            "hours": {
                                "type": "integer",
                                "description": "Time window in hours (default: 24)",
                                "default": 24
                            }
                        }
                    }
                )
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Handle tool calls"""

            if not self.db_manager:
                return [types.TextContent(
                    type="text",
                    text="Error: Database not enabled in honeypot configuration"
                )]

            try:
                if name == "query_recent_events":
                    result = await self._query_recent_events(arguments)
                elif name == "query_by_ip":
                    result = await self._query_by_ip(arguments)
                elif name == "get_attack_statistics":
                    result = await self._get_attack_statistics(arguments)
                elif name == "search_events":
                    result = await self._search_events(arguments)
                elif name == "get_threat_intelligence":
                    result = await self._get_threat_intelligence(arguments)
                elif name == "get_top_attackers":
                    result = await self._get_top_attackers(arguments)
                else:
                    result = f"Unknown tool: {name}"

                return [types.TextContent(type="text", text=str(result))]

            except Exception as e:
                logger.error(f"Tool call error for {name}: {e}")
                return [types.TextContent(
                    type="text",
                    text=f"Error executing {name}: {str(e)}"
                )]

    async def _query_recent_events(self, args: Dict[str, Any]) -> str:
        """Query recent events with filters"""
        limit = args.get('limit', 10)
        service = args.get('service')
        severity = args.get('severity')
        hours = args.get('hours', 24)

        events = self.db_manager.query_events(
            limit=limit,
            service=service,
            severity=severity,
            hours=hours
        )

        if not events:
            return f"No events found in the last {hours} hours"

        # Format output
        output = f"Found {len(events)} events in the last {hours} hours:\n\n"

        for i, event in enumerate(events[:limit], 1):
            output += f"{i}. [{event['severity'].upper()}] {event['event_type']}\n"
            output += f"   Service: {event['service']}\n"
            output += f"   Source: {event['source_ip']}\n"
            output += f"   Time: {event['timestamp']}\n"

            # Add enrichment if available
            if event.get('enrichment'):
                enrichment = event['enrichment']
                if 'geoip' in enrichment:
                    geo = enrichment['geoip']
                    output += f"   Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n"
                if 'reputation' in enrichment:
                    rep = enrichment['reputation']
                    score = rep.get('abuse_confidence_score', 0)
                    output += f"   Abuse Score: {score}/100\n"

            # Add username if present
            if event.get('username'):
                output += f"   Username: {event['username']}\n"

            output += "\n"

        return output

    async def _query_by_ip(self, args: Dict[str, Any]) -> str:
        """Query all events from a specific IP"""
        ip = args['ip']
        limit = args.get('limit', 50)

        # Get events
        events = self.db_manager.query_events(source_ip=ip, limit=limit)

        # Get threat intelligence
        threat_intel = {}
        if self.enrichment_manager:
            threat_intel = self.enrichment_manager.enrich_ip_direct(ip)

        # Format output
        output = f"=== Attack Profile for {ip} ===\n\n"

        # Threat Intelligence
        if threat_intel:
            output += "## Threat Intelligence:\n"

            if 'geoip' in threat_intel:
                geo = threat_intel['geoip']
                output += f"Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n"

            if 'asn' in threat_intel:
                asn = threat_intel['asn']
                output += f"ASN: AS{asn.get('autonomous_system_number')} ({asn.get('autonomous_system_organization', 'Unknown')})\n"

            if 'reputation' in threat_intel:
                rep = threat_intel['reputation']
                score = rep.get('abuse_confidence_score', 0)
                risk = rep.get('risk_level', 'unknown')
                reports = rep.get('total_reports', 0)
                output += f"Abuse Score: {score}/100 (Risk: {risk}, Reports: {reports})\n"

            output += "\n"

        # Events
        output += f"## Attack Activity ({len(events)} events):\n\n"

        # Group by service
        by_service = {}
        for event in events:
            service = event.get('service', 'unknown')
            by_service[service] = by_service.get(service, 0) + 1

        output += "Services targeted:\n"
        for service, count in by_service.items():
            output += f"  - {service}: {count} events\n"

        output += "\n## Recent Events:\n\n"

        for i, event in enumerate(events[:10], 1):
            output += f"{i}. {event['event_type']} ({event['timestamp']})\n"
            if event.get('username'):
                output += f"   Username: {event['username']}\n"

        return output

    async def _get_attack_statistics(self, args: Dict[str, Any]) -> str:
        """Get aggregate statistics"""
        hours = args.get('hours', 24)

        stats = self.db_manager.get_statistics(hours=hours)

        output = f"=== Attack Statistics (Last {hours} hours) ===\n\n"
        output += f"Total Events: {stats.get('total_events', 0)}\n\n"

        # By service
        output += "By Service:\n"
        for service, count in stats.get('by_service', {}).items():
            output += f"  - {service}: {count}\n"

        output += "\nBy Severity:\n"
        for severity, count in stats.get('by_severity', {}).items():
            output += f"  - {severity}: {count}\n"

        output += "\nTop 10 Attackers:\n"
        for i, attacker in enumerate(stats.get('top_attackers', [])[:10], 1):
            output += f"  {i}. {attacker['ip']}: {attacker['count']} events\n"

        return output

    async def _search_events(self, args: Dict[str, Any]) -> str:
        """Search events by criteria"""
        event_type = args.get('event_type')
        username = args.get('username')
        limit = args.get('limit', 20)
        hours = args.get('hours', 24)

        # Build filters
        filters = {'limit': limit, 'hours': hours}
        if event_type:
            filters['event_type'] = event_type

        events = self.db_manager.query_events(**filters)

        # Filter by username if specified (since db might not support direct username filter)
        if username:
            events = [e for e in events if e.get('username') == username]

        output = f"Found {len(events)} matching events:\n\n"

        for i, event in enumerate(events[:limit], 1):
            output += f"{i}. {event['event_type']} - {event['source_ip']}\n"
            output += f"   Time: {event['timestamp']}\n"
            if event.get('username'):
                output += f"   Username: {event['username']}\n"

        return output

    async def _get_threat_intelligence(self, args: Dict[str, Any]) -> str:
        """Get threat intelligence for an IP"""
        ip = args['ip']

        if not self.enrichment_manager:
            return "Error: Enrichment not enabled in honeypot configuration"

        threat_intel = self.enrichment_manager.enrich_ip_direct(ip)

        if not threat_intel:
            return f"No threat intelligence available for {ip}"

        output = f"=== Threat Intelligence for {ip} ===\n\n"

        if 'geoip' in threat_intel:
            geo = threat_intel['geoip']
            output += "## Geolocation:\n"
            output += f"Country: {geo.get('country_name', 'Unknown')} ({geo.get('country', 'Unknown')})\n"
            output += f"City: {geo.get('city', 'Unknown')}\n"
            output += f"Coordinates: {geo.get('latitude')}, {geo.get('longitude')}\n"
            output += f"Timezone: {geo.get('timezone', 'Unknown')}\n\n"

        if 'asn' in threat_intel:
            asn = threat_intel['asn']
            output += "## Network:\n"
            output += f"ASN: AS{asn.get('autonomous_system_number', 'N/A')}\n"
            output += f"Organization: {asn.get('autonomous_system_organization', 'Unknown')}\n\n"

        if 'reputation' in threat_intel:
            rep = threat_intel['reputation']
            output += "## Reputation:\n"
            output += f"Abuse Confidence Score: {rep.get('abuse_confidence_score', 0)}/100\n"
            output += f"Risk Level: {rep.get('risk_level', 'unknown').upper()}\n"
            output += f"Total Reports: {rep.get('total_reports', 0)}\n"
            output += f"Whitelisted: {'Yes' if rep.get('is_whitelisted') else 'No'}\n"
            output += f"Tor Exit Node: {'Yes' if rep.get('is_tor') else 'No'}\n"

        return output

    async def _get_top_attackers(self, args: Dict[str, Any]) -> str:
        """Get top attacking IPs"""
        limit = args.get('limit', 10)
        hours = args.get('hours', 24)

        stats = self.db_manager.get_statistics(hours=hours)
        top_attackers = stats.get('top_attackers', [])[:limit]

        output = f"=== Top {limit} Attackers (Last {hours} hours) ===\n\n"

        for i, attacker in enumerate(top_attackers, 1):
            ip = attacker['ip']
            count = attacker['count']

            output += f"{i}. {ip} ({count} events)\n"

            # Get threat intel if available
            if self.enrichment_manager:
                threat_intel = self.enrichment_manager.enrich_ip_direct(ip)
                if 'geoip' in threat_intel:
                    geo = threat_intel['geoip']
                    output += f"   Location: {geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}\n"
                if 'reputation' in threat_intel:
                    rep = threat_intel['reputation']
                    output += f"   Abuse Score: {rep.get('abuse_confidence_score', 0)}/100\n"

            output += "\n"

        return output

    async def run(self):
        """Run the MCP server"""
        if not MCP_AVAILABLE:
            raise ImportError("mcp library required. Install with: pip install mcp")

        logger.info("Starting Honeypot MCP Server...")

        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Honeypot MCP Server")
    parser.add_argument(
        '--config',
        default='honeypot_config.yaml',
        help='Path to honeypot configuration file'
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create and run server
    server = HoneypotMCPServer(config_path=args.config)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
