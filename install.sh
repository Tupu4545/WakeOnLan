#!/bin/bash

# Ensure script is run with standard permissions but accesses sudo when required
set -e

# Warning and Confirmation
echo "============================================================"
echo "⚠️  WARNING: System Configuration Script"
echo "This script will download the WakeOnLan bot and may prompt"
echo "for 'sudo' privileges to install system packages (Python/Git)"
echo "and fully configure a systemctl background service if chosen."
echo ""
echo "Please review the script contents on GitHub before proceeding:"
echo "https://github.com/Tupu4545/WakeOnLan"
echo "============================================================"
printf "Do you wish to continue? (y/n): "
read -r CONTINUE_ANS
if [ "$CONTINUE_ANS" != "y" ] && [ "$CONTINUE_ANS" != "Y" ]; then
    echo "Installation aborted by user."
    exit 0
fi

# ASCII Art
cat <<'EOF'
 __          __   _         ____        _                 
 \ \        / /  | |       / __ \      | |                
  \ \  /\  / /_ _| | _____| |  | |_ __ | |     __ _ _ __  
   \ \/  \/ / _` | |/ / _ \ |  | | '_ \| |    / _` | '_ \ 
    \  /\  / (_| |   <  __/ |__| | | | | |___| (_| | | | |
     \/  \/ \__,_|_|\_\___|\____/|_| |_|______\__,_|_| |_|
                                                          
                                                          
                                                     
                          Tupu4545
EOF

echo ""
echo "Starting installation..."

# Package Manager Detection & Installation
if command -v apt >/dev/null 2>&1; then
    PKG_MAN="sudo apt"
    PKG_INSTALL="install -y"
    PKGS="git python3 python3-venv"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MAN="sudo dnf"
    PKG_INSTALL="install -y"
    PKGS="git python3"
elif command -v yum >/dev/null 2>&1; then
    PKG_MAN="sudo yum"
    PKG_INSTALL="install -y"
    PKGS="git python3"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MAN="sudo pacman"
    PKG_INSTALL="-S --noconfirm"
    PKGS="git python"
elif command -v apk >/dev/null 2>&1; then
    PKG_MAN="sudo apk"
    PKG_INSTALL="add --no-cache"
    PKGS="git python3"
else
    echo "Unsupported package manager. Please install git, python3, and python3-venv manually."
    exit 1
fi

echo "Updating dependencies via package manager..."
$PKG_MAN $PKG_INSTALL $PKGS || {
    echo "Failed to install dependencies. Please run as a user with sudo privileges."
    exit 1
}

# Clone the Repository
CLONE_DIR="WakeOnLan"
if [ ! -d "$CLONE_DIR" ]; then
    echo "Cloning repository..."
    git clone https://github.com/Tupu4545/WakeOnLan.git "$CLONE_DIR"
else
    echo "Directory '$CLONE_DIR' already exists. Skipping clone."
fi

cd "$CLONE_DIR" || exit 1

# Setup Python Virtual Environment
echo "Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Source virtual environment
# shellcheck source=/dev/null
. venv/bin/activate

echo "Installing Python requirements..."

echo "--- Python Environment Diagnostics ---"
echo "python:  $(which python || echo 'not found') ($(python --version 2>/dev/null || echo 'N/A'))"
echo "python3: $(which python3 || echo 'not found') ($(python3 --version 2>/dev/null || echo 'N/A'))"
echo "pip:     $(which pip || echo 'not found') ($(pip --version 2>/dev/null || echo 'N/A'))"
echo "pip3:    $(which pip3 || echo 'not found') ($(pip3 --version 2>/dev/null || echo 'N/A'))"
echo "--------------------------------------"

# Explicitly use the python3 module execution method natively inside the local venv
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# Interactive .env wizard
echo ""
echo "============================================================"
echo "Bot Configuration Wizard"
echo "Leave tokens blank if you don't wish to enable that platform."
echo "============================================================"

printf "Do you want to run in Failover mode (High Availability)? (y/n): "
read -r FAILOVER_ANS
if [ "$FAILOVER_ANS" = "y" ] || [ "$FAILOVER_ANS" = "Y" ]; then
    FAILOVER_ENABLED="yes"
    printf "Is this the Primary node? (y/n): "
    read -r PRIMARY_ANS
    if [ "$PRIMARY_ANS" = "y" ] || [ "$PRIMARY_ANS" = "Y" ]; then
        PRIMARY_DEVICE="yes"
        printf "Enter the IP address of the SECONDARY (Backup) node: "
        read -r SECONDARY_IP
        PRIMARY_IP=""
    else
        PRIMARY_DEVICE="no"
        printf "Enter the IP address of the PRIMARY node: "
        read -r PRIMARY_IP
        SECONDARY_IP=""
    fi
else
    FAILOVER_ENABLED="no"
    PRIMARY_DEVICE="yes"
    SECONDARY_IP=""
    PRIMARY_IP=""
fi

# Telegram variables
printf "Enter Telegram Bot Token (leave blank to skip): "
read -r TELEGRAM_BOT_TOKEN
printf "Enter Telegram Authorized User IDs (comma separated, leave blank to skip): "
read -r TELEGRAM_AUTHORIZED_USERS

# Discord variables
printf "Enter Discord Bot Token (leave blank to skip): "
read -r DISCORD_BOT_TOKEN
printf "Enter Discord Authorized User IDs (comma separated, leave blank to skip): "
read -r DISCORD_AUTHORIZED_USERS
printf "Enter Discord Global Channel ID (leave blank for DM-only mode): "
read -r DISCORD_CHANNEL_ID

# Write to .env
echo "Generating .env file..."
cat > .env <<EOL
# ── Failover ──
FAILOVER_ENABLED=${FAILOVER_ENABLED}
PRIMARY_DEVICE=${PRIMARY_DEVICE}
SECONDARY_IP=${SECONDARY_IP}
PRIMARY_IP=${PRIMARY_IP}
HEARTBEAT_PORT=12345
MONITOR_INTERVAL=30

# ── Telegram ──
TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
TELEGRAM_AUTHORIZED_USERS=${TELEGRAM_AUTHORIZED_USERS}

# ── Discord ──
DISCORD_BOT_TOKEN=${DISCORD_BOT_TOKEN}
DISCORD_AUTHORIZED_USERS=${DISCORD_AUTHORIZED_USERS}
DISCORD_CHANNEL_ID=${DISCORD_CHANNEL_ID}
EOL
chmod 600 .env

# systemd Integration
echo ""
echo "============================================================"
printf "Would you like to install the bot as a persistent systemd background service? (y/n): "
read -r SYSTEMD_ANS

if [ "$SYSTEMD_ANS" = "y" ] || [ "$SYSTEMD_ANS" = "Y" ]; then
    echo "Setting up systemd service (sudo required)..."
    SERVICE_FILE="/etc/systemd/system/wol-bot.service"
    WORKING_DIR=$(pwd)
    CURRENT_USER=$(id -un)
    
    # Create the service file directly into the systemd path using sudo tee
    sudo tee "$SERVICE_FILE" > /dev/null <<EOL
[Unit]
Description=WakeOnLan Discord/Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${CURRENT_USER}
WorkingDirectory=${WORKING_DIR}
ExecStart=${WORKING_DIR}/venv/bin/python ${WORKING_DIR}/main.py
Restart=always
RestartSec=10
EnvironmentFile=${WORKING_DIR}/.env

[Install]
WantedBy=multi-user.target
EOL

    sudo systemctl daemon-reload
    sudo systemctl enable --now wol-bot.service
    echo "✅ systemd service 'wol-bot' installed and started successfully!"
    echo "You can check its status using: sudo systemctl status wol-bot"
    echo "You can check its logs using: sudo journalctl -fu wol-bot"
else
    echo "Skipping systemd installation."
fi

echo ""
echo "============================================================"
echo "🎉 Installation complete!"
echo "If you bypassed systemd configuration, you can start the bot manually by running:"
echo "cd ${CLONE_DIR} && source venv/bin/activate && python3 main.py"
echo ""
echo "⭐️ If you find this project useful, please consider starring"
echo "   the repository on GitHub to support its development!"
echo "   https://github.com/Tupu4545/WakeOnLan"
echo "============================================================"
