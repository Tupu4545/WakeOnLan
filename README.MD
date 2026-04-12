# WakeOnLan Telegram & Discord Manager

A powerful bot for remotely managing your devices via Wake-on-LAN, SSH, and power control commands. Control multiple Windows, Linux, and macOS machines from Telegram and Discord with a persistent 3-message UI.

**View original source and credit:** [https://github.com/Tupu4545/WakeOnLan](https://github.com/Tupu4545/WakeOnLan)

---

## 📷 Setup Preview

*[setup visual/screenshot placeholder]*

---

## 🌟 Features

- **Wake-on-LAN** — Remotely wake sleeping devices
- **Power Management** — Shutdown, restart, and sleep commands
- **Device Status** — Check if devices are online via ping/SSH with 5-second automatic fallback timeout
- **Live Stats Dashboard** — Auto-refreshing status of all devices, bot uptime, and failover health
- **3-Message Persistent UI** — Control panel, stats dashboard, and action log that survive restarts
- **Multi-Device Support** — Manage unlimited devices
- **Dual Platform** — Works on both Telegram and Discord natively
- **Discord DM Support** — Control interface injected directly into authorized users' DMs
- **Active-Passive Failover** — Automatic takeover if the primary node goes down
- **Background Monitoring** — Periodic device status checks with online/offline history every 30 seconds
- **User Authentication** — Restrict access via Telegram User IDs or Discord User IDs
- **Lightweight** — Highly optimized hardware efficiency to run on a Raspberry Pi

---

## 🌐 Network Notice

**Important:** This bot must reside within the **same local broadcast domain (LAN)** as the target devices (or be bridged via a VPN) for the Wake-on-LAN (WoL) UDP magic packets to successfully wake devices. 

Other functions such as SSH shutdown, reboot, and ping checks work flawlessly over any standard routed network regardless of the broadcast domain, provided the ports are accessible.

---

## 📋 Prerequisites

- A Telegram Bot Token (from [@BotFather](https://t.me/botfather)) and/or a Discord Bot Token (from the [Discord Developer Portal](https://discord.com/developers/applications))
- Devices must support:
  - Wake-on-LAN (for wake functionality)
  - SSH access (for shutdown/restart/status reporting over standard routed networks)

---

## 🚀 Installation

You can install the bot automatically via our setup script or manually line-by-line.

### Option 1: Automatic Installation (Recommended)

Run the following command cleanly to deploy the virtual environment, install dependencies, map your `.env` tokens, and establish a permanent background `systemctl` daemon service automatically.

> **Note:** The script will request `sudo` permissions to install OS-level dependencies (`python3`, `git`) and write the systemd unit file. Please review the [install script source](https://github.com/Tupu4545/WakeOnLan/blob/main/install.sh) before executing it on your machine.

```bash
bash <(curl -s https://raw.githubusercontent.com/Tupu4545/WakeOnLan/main/install.sh)
```

### Option 2: Manual Installation

If you prefer to configure everything manually, follow the steps below:

#### 1. Clone the Repository
```bash
git clone https://github.com/Tupu4545/WakeOnLan.git
cd WakeOnLan
```

#### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Configure Environment Variables
Copy the example file and modify it with your credentials:
```bash
cp example.env .env
nano .env
```
*(Leave Telegram or Discord tokens blank if you only wish to deploy one platform.)*

#### 5. Configure Devices Inventory
Create a `devices.json` file to house your machines locally.
```json
{
  "Windows-PC": {
    "ip": "192.168.1.100",
    "mac": "AA:BB:CC:DD:EE:FF",
    "os": "windows",
    "user": "Administrator",
    "port": 22,
    "ssh_key": null
  }
}
```

#### 6. (Optional) Run as a systemd Service
To ensure 24/7 uptime through device restarts, create a systemd service:

```bash
sudo nano /etc/systemd/system/wol-bot.service
```

```ini
[Unit]
Description=WakeOnLan Discord/Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=pi
WorkingDirectory=/path/to/WakeOnLan
ExecStart=/path/to/WakeOnLan/venv/bin/python /path/to/WakeOnLan/main.py
Restart=always
RestartSec=10
EnvironmentFile=/path/to/WakeOnLan/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wol-bot.service
```

---

## 🔧 SSH Setup

For shutdown/restart commands, configure passwordless SSH:

```bash
# Generate SSH key
ssh-keygen -t rsa -b 4096

# Copy to remote device
ssh-copy-id user@device-ip

# Allow passwordless shutdown/reboot/suspend on the remote device
sudo visudo
# Add: yourusername ALL=(ALL) NOPASSWD: /sbin/shutdown, /sbin/reboot, /usr/bin/systemctl suspend
```

---

## 💡 Optimization & Troubleshooting Tips

These are generalized tips derived from real-world deployments on constrained hardware (like Raspberry Pi Zeros):

### 1. Low-Memory Devices (< 512MB RAM)
Running both the Telegram and Discord clients concurrently alongside background parallel-ping monitors can edge out limited memory resources, especially if running other services simultaneously like Pi-hole or AdGuard.
* **Tip:** If the bot regularly crashes due to Out of Memory (OOM) kills, gracefully disable the Discord side by simply clearing out `DISCORD_BOT_TOKEN=` inside your `.env`. It will inherently fallback to running exclusively as an ultra-lightweight Telegram bot without breaking core functionality.

### 2. "Split-Brain" Failover Issues
If you configure an active-passive failover arrangement and suddenly start receiving completely duplicate module messages in your chat UI:
* **Tip:** Check your local firewall software (`ufw` or `iptables`) on the **Primary Node** and ensure it allows incoming TCP traffic across your designated `HEARTBEAT_PORT` (default `12345`). If the Backup Node cannot successfully reach this port periodically, it assumes the primary is natively dead and mistakenly spins up its own twin bot instance over it.

### 3. VPNs (Tailscale / WireGuard) limitations
Because the bot supports executing commands via standard SSH tunnels, pinging and power management commands will work universally regardless of how your network traverses virtual subnets or VPNs like Tailscale.
* **Tip:** However, **Wake-on-LAN (WoL)** relies exclusively on Layer-2 network broadcast UDP packets. These packets are natively dropped across routed VPN tunnels or VLAN boundaries! You must place the bot hardware inside the exact same local subnet as the target device to wake it, *unless* you configure advanced subnet broadcast-relay routing. Stick to providing local intranet IP topologies into your `devices.json`!
