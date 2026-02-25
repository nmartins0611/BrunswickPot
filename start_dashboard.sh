#!/bin/bash
# Quick launcher for BrunswickPot Terminal Dashboard

echo "🛡️  Starting BrunswickPot Terminal Dashboard..."
echo ""

# Check if textual is installed
if ! python3 -c "import textual" 2>/dev/null; then
    echo "❌ Textual library not found. Installing dependencies..."
    pip install textual rich
    echo ""
fi

# Check if database exists
if [ ! -f "data/honeypot_events.db" ]; then
    echo "⚠️  Warning: Database not found at data/honeypot_events.db"
    echo "   Make sure the honeypot is running and has created events."
    echo ""
fi

# Run the TUI
python3 gui/tui.py "$@"
