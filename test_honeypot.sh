#!/bin/bash

echo "🧪 Testing BrunswickPot Honeypot Services..."
echo "============================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test SSH
echo -e "\n${YELLOW}Testing SSH honeypot (port 2222)...${NC}"
for user in root admin ubuntu pi guest; do
    echo "  Attempting SSH as '$user'..."
    timeout 3 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                  -o PubkeyAuthentication=no -p 2222 $user@localhost exit 2>&1 | grep -q "Permission denied\|password:" && \
        echo -e "    ${GREEN}✓${NC} Connection captured" || \
        echo -e "    ${RED}✗${NC} Connection failed"
done

# Test HTTP
echo -e "\n${YELLOW}Testing HTTP honeypot (port 8000)...${NC}"
suspicious_paths=(
    "/"
    "/admin"
    "/.env"
    "/wp-admin"
    "/phpmyadmin"
    "/.git/config"
    "/backup"
    "/.aws/credentials"
)

for path in "${suspicious_paths[@]}"; do
    echo "  Testing path: $path"
    status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000$path 2>/dev/null)
    if [ ! -z "$status" ]; then
        echo -e "    ${GREEN}✓${NC} Response: $status"
    else
        echo -e "    ${RED}✗${NC} No response"
    fi
done

# Test with suspicious user agents
echo -e "\n${YELLOW}Testing suspicious user agents...${NC}"
user_agents=(
    "sqlmap/1.0"
    "Metasploit"
    "Nikto"
    "nmap"
)

for ua in "${user_agents[@]}"; do
    echo "  Testing UA: $ua"
    curl -A "$ua" -s http://localhost:8000/ > /dev/null && \
        echo -e "    ${GREEN}✓${NC} Request captured" || \
        echo -e "    ${RED}✗${NC} Request failed"
done

# Test SMB (if smbclient is available)
echo -e "\n${YELLOW}Testing SMB honeypot (port 4445)...${NC}"
if command -v smbclient &> /dev/null; then
    timeout 3 smbclient -L localhost -p 4445 -N 2>&1 | grep -q "Sharename\|session setup failed" && \
        echo -e "  ${GREEN}✓${NC} SMB connection captured" || \
        echo -e "  ${RED}✗${NC} SMB connection failed"
else
    echo -e "  ${YELLOW}⚠${NC} smbclient not installed, skipping"
fi

# Test LDAP (if ldapsearch is available)
echo -e "\n${YELLOW}Testing LDAP honeypot (port 3389)...${NC}"
if command -v ldapsearch &> /dev/null; then
    timeout 3 ldapsearch -H ldap://localhost:3389 -x -b "DC=company,DC=com" 2>&1 | grep -q "result:\|Can't contact" && \
        echo -e "  ${GREEN}✓${NC} LDAP connection captured" || \
        echo -e "  ${RED}✗${NC} LDAP connection failed"
else
    echo -e "  ${YELLOW}⚠${NC} ldapsearch not installed, skipping"
fi

# Summary
echo -e "\n${GREEN}============================================${NC}"
echo -e "${GREEN}✅ Test complete!${NC}"
echo ""
echo "To view results:"
echo "  1. Check dashboard: ./start_dashboard.sh"
echo "  2. View database:   sqlite3 ./data/honeypot_events.db 'SELECT * FROM honeypot_events ORDER BY timestamp DESC LIMIT 10;'"
echo "  3. Check logs:      podman logs brunswickpot"
echo "  4. Kafka topic:     kcat -b 192.168.88.176:9092 -t honey -C"
