# BrunswickPot - Enterprise Honeypot System

**Advanced multi-service honeypot with threat intelligence enrichment and AI-assisted analysis**

BrunswickPot is an enterprise-grade honeypot system that simulates multiple services (SSH, SMB, HTTP, LDAP) to detect, analyze, and track cyber attacks. It features real-time threat intelligence enrichment, multiple output destinations (Kafka, Splunk, Elasticsearch, Database), and AI integration via Model Context Protocol.

## Features

### 🎯 Multi-Service Honeypots
- **SSH** - Captures authentication attempts, usernames, passwords, public keys, and commands
- **SMB** - Simulates Windows file server (CIFS/SMB protocol)
- **HTTP** - Fake web server with configurable content and path detection
- **LDAP** - Directory service simulation

### 🔍 Threat Intelligence Enrichment
- **GeoIP** - Offline IP geolocation using MaxMind GeoLite2 (city, country, coordinates)
- **ASN** - Autonomous System Number and ISP information
- **AbuseIPDB** - IP reputation scores and abuse confidence
- **Caching** - LRU cache with TTL to minimize API calls

### 📊 Event Destinations
- **Database** - Local SQLite or PostgreSQL for forensics
- **Kafka** - Real-time event streaming
- **Splunk** - HTTP Event Collector (HEC) integration
- **Elasticsearch** - Full-text search with daily index rotation
- **Webhook** - Custom HTTP endpoints

### 🤖 AI Integration
- **MCP Server** - Model Context Protocol for Claude and AI assistants
- **Natural Language Queries** - Ask about attacks in plain English
- **Automated Analysis** - AI-assisted threat profiling

### 🖥️ Terminal Dashboard (TUI)
- **Real-time Monitoring** - Live statistics and event feed
- **Beautiful Interface** - Clean, colorful terminal UI using Textual
- **Top Attackers** - See most active IPs with geolocation and risk scores
- **Service Analytics** - Monitor activity across all honeypot services
- **Auto-refresh** - Updates every 5 seconds automatically

### 📈 Advanced Capabilities
- Session tracking across services
- Attack tool detection (nmap, sqlmap, Metasploit, etc.)
- Credential harvesting
- SQL injection detection
- Rate limiting and auto-blocking
- Retention policies
- Batch processing and retry logic

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/BrunswickPot.git
cd BrunswickPot

# Copy and edit configuration
cp honeypot_config.yaml.example honeypot_config.yaml
nano honeypot_config.yaml

# Build and start
docker-compose up -d

# View logs
docker-compose logs -f honeypot

# Stop
docker-compose down
```

**Ports exposed by default:**
- `2222` - SSH honeypot
- `8000` - HTTP honeypot
- `3389` - LDAP honeypot
- `4445` - SMB honeypot

**Data persistence:** Events are stored in `./data` directory on the host.

### Option 2: Manual Installation

```bash
# Clone repository
git clone https://github.com/yourusername/BrunswickPot.git
cd BrunswickPot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and edit configuration
cp honeypot_config.yaml.example honeypot_config.yaml
nano honeypot_config.yaml

# Download GeoIP databases (free license key required)
# Sign up at: https://www.maxmind.com/en/geolite2/signup
sudo python scripts/download_geoip.py --license-key YOUR_LICENSE_KEY

# Setup database
python scripts/setup_database.py
```

### Configuration

Edit `honeypot_config.yaml` to enable desired services and outputs:

```yaml
general:
  honeypot_name: corporate-server-01
  log_level: INFO

# Enable services
services:
  ssh:
    enabled: true
    port: 2222  # Use 22 for production (requires root)

  smb:
    enabled: true
    port: 4445

  http:
    enabled: true
    port: 8000

# Enable outputs
database:
  enabled: true
  type: sqlite
  sqlite_path: /var/lib/honeypot/events.db

kafka:
  enabled: true
  bootstrap_servers:
    - localhost:9092
  topic: honeypot-events

# Enable enrichment
enrichment:
  enabled: true
  geoip:
    enabled: true
    database_path: /var/lib/GeoIP/GeoLite2-City.mmdb
```

### Running

```bash
# Start honeypot
python -m honeypot.main

# Or with custom config
python -m honeypot.main --config /path/to/config.yaml

# Test configuration
python -m honeypot.main --test-config
```

## Terminal Dashboard

Monitor your honeypot in real-time with a beautiful terminal interface:

```bash
# Quick start
./start_dashboard.sh

# Or run directly
python gui/tui.py

# With custom config
python gui/tui.py --config /path/to/config.yaml
```

**Features:**
- 📊 Live statistics (total events, recent activity, unique IPs, credentials)
- ⚠️ Severity breakdown (Critical, High, Medium, Low)
- 🛠️ Service analytics (SSH, HTTP, SMB, LDAP)
- 🎯 Top attackers with geolocation and risk scores
- 📝 Real-time event log with detailed attack information
- 🔄 Auto-refresh every 5 seconds

**Keyboard shortcuts:**
- `q` - Quit
- `r` - Manual refresh
- `c` - Clear filters

See `gui/README.md` for more details.

## MCP Server (AI Integration)

The MCP server allows AI assistants like Claude to query honeypot data:

```bash
# Start MCP server
python -m mcp_server.server --config honeypot_config.yaml
```

### Available MCP Tools

1. **query_recent_events** - Get recent attacks with filtering
2. **query_by_ip** - Full attacker profile for specific IP
3. **get_attack_statistics** - Aggregate metrics and statistics
4. **search_events** - Search by event type or username
5. **get_threat_intelligence** - IP reputation and geolocation
6. **get_top_attackers** - List of most active attackers

### Example AI Queries

```
"What SSH attacks did I see in the last hour?"
"Show me the profile for IP 1.2.3.4"
"Which countries are most attacks coming from?"
"What usernames are attackers trying?"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Honeypot Services                        │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐                   │
│  │ SSH  │  │ SMB  │  │ HTTP │  │ LDAP │                   │
│  └──┬───┘  └──┬───┘  └──┬───┘  └──┬───┘                   │
└─────┼─────────┼─────────┼─────────┼───────────────────────┘
      │         │         │         │
      └─────────┴─────────┴─────────┘
                │
                ▼
   ┌────────────────────────────┐
   │  Attacker Profiler         │
   │  Session Tracking          │
   └────────────┬───────────────┘
                │
                ▼
   ┌────────────────────────────┐
   │  Enrichment Manager        │
   │  ├─ GeoIP                  │
   │  ├─ ASN                    │
   │  ├─ AbuseIPDB              │
   │  └─ Cache (LRU+TTL)        │
   └────────────┬───────────────┘
                │
                ▼
   ┌────────────────────────────┐
   │  Event Reporter            │
   └────────────┬───────────────┘
                │
      ┌─────────┼─────────┬──────────┬────────────┐
      ▼         ▼         ▼          ▼            ▼
  ┌────────┐ ┌──────┐ ┌────────┐ ┌──────────┐ ┌────────┐
  │Database│ │Kafka │ │Splunk  │ │Elasticsearch│ │Webhook│
  └────────┘ └──────┘ └────────┘ └──────────┘ └────────┘
                │
                ▼
         ┌──────────────┐
         │  MCP Server  │  ◄──── AI Assistants
         └──────────────┘
```

## Event Schema

Events are enriched with comprehensive metadata:

```json
{
  "timestamp": "2026-02-25T10:30:00Z",
  "honeypot_id": "corporate-server-01",
  "event_type": "ssh_auth_attempt",
  "service": "ssh",
  "severity": "high",
  "source_ip": "1.2.3.4",
  "source_port": 54321,
  "username": "root",
  "password": "password123",
  "attacker_session": {
    "first_seen": "2026-02-25T10:25:00Z",
    "total_events": 15,
    "is_repeat_attacker": true
  },
  "enrichment": {
    "geoip": {
      "country": "CN",
      "city": "Beijing",
      "latitude": 39.9042,
      "longitude": 116.4074
    },
    "asn": {
      "autonomous_system_number": 4134,
      "autonomous_system_organization": "Chinanet"
    },
    "reputation": {
      "abuse_confidence_score": 95,
      "risk_level": "critical",
      "total_reports": 42
    }
  }
}
```

## Production Deployment

### System Requirements

- Docker 20.10+ and Docker Compose 1.29+ (for containerized deployment)
- OR Python 3.9+ (for manual deployment)
- 2GB RAM (minimum), 4GB recommended
- 10GB disk space for logs/database
- Network access for threat intelligence APIs

### Docker Production Deployment

#### Using Standard Ports (Requires Root/Privileged)

Edit `docker-compose.yml`:

```yaml
services:
  honeypot:
    ports:
      - "22:2222"    # Map host 22 to container SSH
      - "80:8000"    # Map host 80 to container HTTP
      - "389:3389"   # Map host 389 to container LDAP
      - "445:4445"   # Map host 445 to container SMB
    cap_add:
      - NET_BIND_SERVICE
```

Or run with privileged mode:
```yaml
    privileged: true
```

#### With Kafka Stack

Uncomment the Kafka service in `docker-compose.yml` and update `honeypot_config.yaml`:

```yaml
kafka:
  enabled: true
  bootstrap_servers:
    - kafka:9092
  topic: honey
```

Then:
```bash
docker-compose up -d
```

#### With Elasticsearch Stack

Uncomment the Elasticsearch service in `docker-compose.yml` and update `honeypot_config.yaml`:

```yaml
elasticsearch:
  enabled: true
  hosts:
    - http://elasticsearch:9200
```

#### Resource Limits

Add to `docker-compose.yml`:

```yaml
services:
  honeypot:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 1G
```

### Using Standard Ports (Requires Root)

```yaml
services:
  ssh:
    port: 22    # Standard SSH port
  http:
    port: 80    # Standard HTTP port
  ldap:
    port: 389   # Standard LDAP port
  smb:
    port: 445   # Standard SMB port
```

Run with capabilities instead of full root:
```bash
sudo setcap 'cap_net_bind_service=+ep' /path/to/python
```

### Systemd Service

Create `/etc/systemd/system/brunswickpot.service`:

```ini
[Unit]
Description=BrunswickPot Honeypot System
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/brunswickpot
ExecStart=/opt/brunswickpot/venv/bin/python -m honeypot.main
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable brunswickpot
sudo systemctl start brunswickpot
sudo systemctl status brunswickpot
```

## Security Considerations

⚠️ **Important Security Notes:**

1. **Isolation** - Run in isolated network segment or VM
2. **No Real Services** - Don't run alongside production services
3. **Firewall** - Restrict outbound connections if possible
4. **Credentials** - Captured passwords are stored - secure your database
5. **Legal** - Ensure compliance with local laws and policies
6. **Monitoring** - Monitor the honeypot itself for compromise

## Troubleshooting

### Database Issues

```bash
# Verify database setup
python scripts/setup_database.py --verify-only

# Check database location
sqlite3 /var/lib/honeypot/events.db "SELECT COUNT(*) FROM honeypot_events;"
```

### Kafka Connection Issues

```bash
# Test Kafka connectivity
kafkacat -b localhost:9092 -L

# Check Kafka producer health
python -c "from honeypot.producers.kafka_producer import KafkaProducer; \
           p = KafkaProducer({'enabled': True, 'bootstrap_servers': ['localhost:9092'], 'topic': 'test'}); \
           print(p.health_check())"
```

### GeoIP Not Working

```bash
# Verify database files exist
ls -lh /var/lib/GeoIP/

# Test GeoIP lookup
python -c "import geoip2.database; \
           reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb'); \
           print(reader.city('8.8.8.8'))"
```

## Development

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/

# Run with coverage
pytest --cov=honeypot tests/
```

### Project Structure

```
BrunswickPot/
├── honeypot/              # Main package
│   ├── producers/         # Event output destinations
│   ├── services/          # Honeypot services
│   ├── enrichment/        # Threat intelligence
│   ├── database/          # Persistence layer
│   └── main.py            # Application entry point
├── mcp_server/            # AI integration
├── scripts/               # Setup and utility scripts
├── tests/                 # Unit tests
├── honeypot_config.yaml   # Configuration
└── requirements.txt       # Dependencies
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

[Add your license here]

## Credits

- MaxMind GeoIP2 for geolocation data
- AbuseIPDB for IP reputation
- Paramiko for SSH protocol implementation

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/BrunswickPot/issues
- Documentation: https://brunswickpot.readthedocs.io

---

**Built with ❤️ for cybersecurity research and threat detection**
