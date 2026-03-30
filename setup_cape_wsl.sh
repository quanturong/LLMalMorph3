#!/bin/bash
# =============================================================================
# CAPE Sandbox Setup Script for WSL2
# Designed for LLMalMorph pipeline integration
# =============================================================================
set -e

echo "=============================================="
echo "  CAPE Sandbox Setup for WSL2"
echo "=============================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

CAPE_ROOT="/opt/CAPEv2"
CAPE_USER="cape"

# ---- Step 1: Start MongoDB ----
echo -e "${YELLOW}[1/7] Starting MongoDB...${NC}"
sudo systemctl start mongod 2>/dev/null || true
sudo systemctl enable mongod 2>/dev/null || true
if mongosh --eval "db.runCommand({ping:1})" --quiet 2>/dev/null; then
    echo -e "${GREEN}  ✅ MongoDB running${NC}"
else
    # Try mongod manually if systemd fails
    sudo mkdir -p /var/lib/mongodb /var/log/mongodb
    sudo chown -R mongodb:mongodb /var/lib/mongodb /var/log/mongodb
    sudo mongod --dbpath /var/lib/mongodb --logpath /var/log/mongodb/mongod.log --fork 2>/dev/null || true
    sleep 2
    if mongosh --eval "db.runCommand({ping:1})" --quiet 2>/dev/null; then
        echo -e "${GREEN}  ✅ MongoDB running (manual start)${NC}"
    else
        echo -e "${RED}  ❌ MongoDB failed to start. Check: sudo mongod --dbpath /var/lib/mongodb${NC}"
        echo "     Continuing anyway..."
    fi
fi

# ---- Step 2: Install Python dependencies ----
echo ""
echo -e "${YELLOW}[2/7] Installing system dependencies...${NC}"
sudo apt-get install -y -qq \
    python3-pip python3-venv python3-dev \
    libffi-dev libssl-dev libxml2-dev libxslt1-dev \
    libjpeg-dev zlib1g-dev \
    tcpdump apparmor-utils \
    git unzip p7zip-full \
    yara libyara-dev \
    ssdeep libfuzzy-dev \
    libcap2-bin \
    swig \
    2>&1 | tail -3
echo -e "${GREEN}  ✅ System dependencies installed${NC}"

# ---- Step 3: Create CAPE user ----
echo ""
echo -e "${YELLOW}[3/7] Setting up CAPE user and directories...${NC}"
if ! id "$CAPE_USER" &>/dev/null; then
    sudo adduser --disabled-password --gecos "" $CAPE_USER 2>/dev/null || true
fi
sudo usermod -aG kvm $CAPE_USER 2>/dev/null || true
sudo usermod -aG libvirt $CAPE_USER 2>/dev/null || true

# ---- Step 4: Copy CAPEv2 source ----
echo ""
echo -e "${YELLOW}[4/7] Setting up CAPEv2 at $CAPE_ROOT...${NC}"
if [ -d "$CAPE_ROOT" ]; then
    echo "  CAPEv2 already exists at $CAPE_ROOT"
else
    # Copy from Windows mount
    if [ -d "/mnt/e/CAPEv2" ]; then
        sudo cp -r /mnt/e/CAPEv2 $CAPE_ROOT
        echo -e "${GREEN}  ✅ Copied from /mnt/e/CAPEv2${NC}"
    else
        echo -e "${RED}  ❌ CAPEv2 not found at /mnt/e/CAPEv2${NC}"
        echo "     Please clone: sudo git clone https://github.com/kevoreilly/CAPEv2.git $CAPE_ROOT"
        exit 1
    fi
fi
sudo chown -R $CAPE_USER:$CAPE_USER $CAPE_ROOT

# ---- Step 5: Install Python packages ----
echo ""
echo -e "${YELLOW}[5/7] Installing CAPE Python dependencies...${NC}"
cd $CAPE_ROOT

# Create virtual environment
if [ ! -d "$CAPE_ROOT/venv" ]; then
    sudo -u $CAPE_USER python3 -m venv $CAPE_ROOT/venv
fi

# Install requirements
sudo -u $CAPE_USER $CAPE_ROOT/venv/bin/pip install --upgrade pip setuptools wheel 2>&1 | tail -1
if [ -f "$CAPE_ROOT/requirements.txt" ]; then
    sudo -u $CAPE_USER $CAPE_ROOT/venv/bin/pip install -r $CAPE_ROOT/requirements.txt 2>&1 | tail -3
    echo -e "${GREEN}  ✅ Python dependencies installed${NC}"
else
    echo -e "${YELLOW}  ⚠️  No requirements.txt found, installing core packages...${NC}"
    sudo -u $CAPE_USER $CAPE_ROOT/venv/bin/pip install \
        django pefile yara-python requests pymongo \
        tlsh ssdeep pymisp pycryptodomex \
        2>&1 | tail -3
fi

# ---- Step 6: Configure CAPE for WSL2 ----
echo ""
echo -e "${YELLOW}[6/7] Configuring CAPE...${NC}"

# Copy default configs if not present
CONF_DIR="$CAPE_ROOT/conf"
DEFAULT_DIR="$CAPE_ROOT/conf/default"

if [ -d "$DEFAULT_DIR" ]; then
    for f in "$DEFAULT_DIR"/*.default; do
        basename=$(basename "$f" .default)
        target="$CONF_DIR/${basename}"
        if [ ! -f "$target" ]; then
            sudo -u $CAPE_USER cp "$f" "$target"
            echo "  Copied config: $basename"
        fi
    done
fi

# Configure API
API_CONF="$CONF_DIR/api.conf"
if [ -f "$API_CONF" ]; then
    # Set API to listen on all interfaces
    sudo -u $CAPE_USER sed -i 's/^host\s*=.*/host = 0.0.0.0/' "$API_CONF" 2>/dev/null || true
    sudo -u $CAPE_USER sed -i 's/^port\s*=.*/port = 8090/' "$API_CONF" 2>/dev/null || true
    echo -e "${GREEN}  ✅ API configured: 0.0.0.0:8090${NC}"
fi

# Configure cuckoo.conf
CUCKOO_CONF="$CONF_DIR/cuckoo.conf"
if [ -f "$CUCKOO_CONF" ]; then
    # Set machinery to kvm
    sudo -u $CAPE_USER sed -i 's/^machinery\s*=.*/machinery = kvm/' "$CUCKOO_CONF" 2>/dev/null || true
    # Set result server IP (WSL2 IP)
    WSL_IP=$(hostname -I | awk '{print $1}')
    sudo -u $CAPE_USER sed -i "s/^ip\s*=.*/ip = ${WSL_IP}/" "$CUCKOO_CONF" 2>/dev/null || true
    echo -e "${GREEN}  ✅ Cuckoo configured: machinery=kvm, ip=$WSL_IP${NC}"
fi

# Configure KVM
KVM_CONF="$CONF_DIR/kvm.conf"
if [ -f "$KVM_CONF" ]; then
    echo -e "${YELLOW}  ℹ️  KVM config exists at $KVM_CONF${NC}"
    echo "     You will need to edit this after creating a Windows VM"
fi

# Configure reporting (enable MongoDB)
REPORTING_CONF="$CONF_DIR/reporting.conf"
if [ -f "$REPORTING_CONF" ]; then
    sudo -u $CAPE_USER sed -i '/^\[mongodb\]/,/^\[/{s/^enabled\s*=.*/enabled = yes/}' "$REPORTING_CONF" 2>/dev/null || true
    echo -e "${GREEN}  ✅ MongoDB reporting enabled${NC}"
fi

# tcpdump permissions
sudo chmod +s /usr/sbin/tcpdump 2>/dev/null || true
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump 2>/dev/null || true

echo -e "${GREEN}  ✅ CAPE configured for WSL2${NC}"

# ---- Step 7: Create start script ----
echo ""
echo -e "${YELLOW}[7/7] Creating start/stop scripts...${NC}"

cat > /tmp/cape-start.sh << 'STARTEOF'
#!/bin/bash
# Start CAPE services
echo "Starting CAPE services..."

# Start MongoDB
sudo systemctl start mongod 2>/dev/null || \
    sudo mongod --dbpath /var/lib/mongodb --logpath /var/log/mongodb/mongod.log --fork 2>/dev/null

# Start libvirtd
sudo systemctl start libvirtd 2>/dev/null || true

CAPE_ROOT="/opt/CAPEv2"
VENV="$CAPE_ROOT/venv/bin"

# Run Django migrations (first time)
cd $CAPE_ROOT/web
sudo -u cape $VENV/python manage.py migrate --run-syncdb 2>/dev/null

# Start CAPE main daemon (optional - only needed if you have a Windows guest VM)
# cd $CAPE_ROOT
# sudo -u cape $VENV/python cuckoo.py &
# sleep 3

# Start web API on port 8090
echo "Starting CAPE web API on port 8090..."
cd $CAPE_ROOT/web
nohup sudo -u cape $VENV/python manage.py runserver 0.0.0.0:8090 > /tmp/cape-api.log 2>&1 &
sleep 3

# Start processor
echo "Starting CAPE processor..."
cd $CAPE_ROOT
nohup sudo -u cape $VENV/python utils/process.py auto > /tmp/cape-processor.log 2>&1 &

echo ""
echo "✅ CAPE services started!"
echo "   API: http://localhost:8090"
echo ""
echo "Test with: curl http://localhost:8090/apiv2/tasks/list/"
STARTEOF

cat > /tmp/cape-stop.sh << 'STOPEOF'
#!/bin/bash
echo "Stopping CAPE services..."
sudo pkill -f "cuckoo.py" 2>/dev/null || true
sudo pkill -f "api.py" 2>/dev/null || true
sudo pkill -f "process.py" 2>/dev/null || true
echo "✅ CAPE services stopped"
STOPEOF

sudo mv /tmp/cape-start.sh /opt/CAPEv2/cape-start.sh
sudo mv /tmp/cape-stop.sh /opt/CAPEv2/cape-stop.sh
sudo chmod +x /opt/CAPEv2/cape-start.sh /opt/CAPEv2/cape-stop.sh
sudo chown $CAPE_USER:$CAPE_USER /opt/CAPEv2/cape-start.sh /opt/CAPEv2/cape-stop.sh

echo -e "${GREEN}  ✅ Start script: /opt/CAPEv2/cape-start.sh${NC}"
echo -e "${GREEN}  ✅ Stop script:  /opt/CAPEv2/cape-stop.sh${NC}"

# ---- Summary ----
echo ""
echo "=============================================="
echo -e "${GREEN}  CAPE Installation Complete!${NC}"
echo "=============================================="
echo ""
echo "Installed at: $CAPE_ROOT"
echo "API will be at: http://localhost:8090"
echo ""
echo "NEXT STEPS (manual):"
echo "  1. Create a Windows guest VM for malware analysis:"
echo "     - Download Windows 10 ISO"
echo "     - Create VM: virt-install or virt-manager"
echo "     - Install CAPE agent in the VM"
echo "     - Take snapshot"
echo "     - Edit /opt/CAPEv2/conf/kvm.conf"
echo ""
echo "  2. Start CAPE:"
echo "     sudo /opt/CAPEv2/cape-start.sh"
echo ""
echo "  3. Test from Windows PowerShell:"
echo "     curl http://localhost:8090/apiv2/tasks/list/"
echo ""
