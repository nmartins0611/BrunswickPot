# BrunswickPot Terminal UI

A beautiful terminal-based dashboard for monitoring your honeypot in real-time.

## Features

- 📊 **Live Statistics** - Total events, recent activity, unique IPs, credentials captured
- ⚠️ **Severity Breakdown** - See attacks by severity (Critical, High, Medium, Low)
- 🛠️ **Service Analytics** - Monitor activity across SSH, HTTP, SMB, LDAP services
- 🎯 **Top Attackers** - View most active attacking IPs with geolocation and risk scores
- 📝 **Recent Events** - Real-time event log with detailed attack information
- 🔄 **Auto-Refresh** - Updates every 5 seconds automatically

## Installation

```bash
# Install dependencies
pip install textual rich

# Or use the main requirements file
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Run from the project root
python gui/tui.py
```

### With Custom Config

```bash
python gui/tui.py --config /path/to/honeypot_config.yaml
```

## Keyboard Shortcuts

- `q` - Quit the dashboard
- `r` - Manually refresh data
- `c` - Clear filters (reserved for future use)

## Screenshots

```
┌─────────────────────────────────────────────────────────────────────────┐
│ BrunswickPot TUI                                           🕐 14:23:45  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│ ┌─ Statistics ──┐  ┌─ Severity ────┐  ┌─ Services ────┐              │
│ │ 📊 Total: 1,234│  │ 🔴 Critical: 5 │  │ 🔐 SSH:  450   │              │
│ │ 🔥 Recent: 89  │  │ 🟠 High: 23    │  │ 🌐 HTTP: 234   │              │
│ │ 🌐 IPs: 156    │  │ 🟡 Medium: 45  │  │ 📁 SMB:  123   │              │
│ │ 🔑 Creds: 342  │  │ 🟢 Low: 16     │  │ 📋 LDAP: 45    │              │
│ └────────────────┘  └────────────────┘  └────────────────┘              │
│                                                                         │
│ ┌─ 🎯 Top Attackers ──────────────────────────────────────────────┐    │
│ │ IP              Count  Country  Risk                            │    │
│ │ 192.168.1.100   45     CN       critical                        │    │
│ │ 10.0.0.50       23     RU       high                            │    │
│ └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│ ┌─ 📝 Recent Events ──────────────────────────────────────────────┐    │
│ │ Time     Service  IP            Country  Event          User    │    │
│ │ 14:23:42 ssh      192.168.1.100 CN       auth_attempt   root    │    │
│ │ 14:23:35 http     10.0.0.50     RU       suspicious_req admin   │    │
│ └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│ q Quit │ r Refresh │ c Clear Filters                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

## Requirements

- Python 3.9+
- Textual library
- Rich library
- SQLAlchemy (for database access)
- Running honeypot with database enabled

## Configuration

The TUI reads from the same `honeypot_config.yaml` file as the honeypot. Make sure:

1. Database is enabled in your config:
   ```yaml
   database:
     enabled: true
     type: sqlite
     sqlite_path: ./data/honeypot_events.db
   ```

2. The honeypot has been running and collecting events

## Troubleshooting

### No data showing

- Ensure the honeypot is running: `python -m honeypot.main`
- Check the database file exists: `ls -lh data/honeypot_events.db`
- Verify events are being logged: `sqlite3 data/honeypot_events.db "SELECT COUNT(*) FROM honeypot_events;"`

### TUI not displaying correctly

- Make sure your terminal supports colors and UTF-8
- Try a modern terminal emulator (iTerm2, Windows Terminal, Alacritty, etc.)
- Resize your terminal window if layout appears broken

### Database connection errors

- Check the path in `honeypot_config.yaml` matches the actual database location
- Ensure you have read permissions on the database file

## Features Coming Soon

- Filter events by service, severity, or IP
- Search functionality
- Export data to CSV/JSON
- Detailed event inspection view
- Real-time alerts and notifications
- Customizable refresh interval
- Multiple dashboard views

## License

Part of the BrunswickPot project
