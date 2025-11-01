# Telegram Device Manager Bot

A powerful Telegram bot for remotely managing your devices via Wake-on-LAN, SSH, and power control commands. Control multiple Windows, Linux, and macOS machines from your phone.

## 🌟 Features

- **Wake-on-LAN** - Remotely wake sleeping devices
- **Power Management** - Shutdown, restart, and sleep commands
- **Device Status** - Check if devices are online via ping/SSH
- **Multi-Device Support** - Manage unlimited devices
- **Interactive Menu** - Clean button-based interface
- **Device Management** - Add/remove devices directly from Telegram
- **Persistent UI** - Menu stays visible, status updates dynamically
- **Auto-Monitoring** - Ping loops verify device state changes
- **User Authentication** - Restrict access via Telegram User IDs

## 📋 Prerequisites

- Python 3.8 or higher
- A Telegram Bot Token (from [@BotFather](https://t.me/botfather))
- Devices must support:
  - Wake-on-LAN (for wake functionality)
  - SSH access (for shutdown/restart/status)
  - Proper network configuration

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/telegram-device-manager.git
cd telegram-device-manager
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```properties
TELEGRAM_BOT_TOKEN=your_bot_token_from_botfather
AUTHORIZED_USER_IDS=123456789,987654321
```

**How to get your User ID:**

1. Start the bot without adding your ID
2. Send `/start` to the bot
3. The bot will show your User ID in the error message
4. Add your User ID to `.env` and restart the bot

### 5. Configure Devices

Create a `devices.json` file (or use the bot's add device feature):

```json
{
  "Windows-PC": {
    "ip": "192.168.1.100",
    "mac": "AA:BB:CC:DD:EE:FF",
    "os": "windows",
    "user": "Administrator",
    "port": 22,
    "ssh_key": null
  },
  "Ubuntu-Server": {
    "ip": "192.168.1.200",
    "mac": "11:22:33:44:55:66",
    "os": "linux",
    "user": "admin",
    "port": 22,
    "ssh_key": "/home/user/.ssh/id_rsa"
  }
}
```

### 6. Run the Bot

```bash
python bot.py
```

## ⚙️ Running 24/7 as a Service

To keep your bot running continuously, you can set it up as a `systemd` service on Linux or a Task Scheduler job on Windows.

### 🐧 Linux (Recommended)

1. **Create a `systemd` service file**

    Create and open a service file:

    ```sh
    sudo nano /etc/systemd/system/telegram-bot.service
    ```

    Paste this configuration:

    ```ini
    [Unit]
    Description=Telegram Device Manager Bot
    After=network.target

    [Service]
    Type=simple
    WorkingDirectory=/home/yourusername/telegram-device-manager
    ExecStart=/home/yourusername/telegram-device-manager/venv/bin/python /home/yourusername/telegram-device-manager/bot.py
    Restart=always
    RestartSec=10
    User=yourusername
    Environment=PYTHONUNBUFFERED=1

    [Install]
    WantedBy=multi-user.target
    ```

    > ⚠️ **Important:** Replace `/home/yourusername/telegram-device-manager` with your actual project path and `yourusername` with your username.

2. **Enable and start the service**

    ```sh
    sudo systemctl daemon-reload
    sudo systemctl enable telegram-bot.service
    sudo systemctl start telegram-bot.service
    ```

3. **Check logs and status**

    ```sh
    sudo systemctl status telegram-bot.service
    sudo journalctl -u telegram-bot.service -f
    ```

The bot will now auto-start on boot and restart automatically if it crashes.

---

### 🪟 Windows (Optional)

If you’re running this on Windows, use Task Scheduler to keep it alive.

1. **Create a `.bat` file**
    Inside your project folder, create a file called `start_bot.bat`:

    ```bat
    @echo off
    cd /d "C:\Path\To\telegram-device-manager"
    call venv\Scripts\activate
    python bot.py
    ```

    > ⚠️ **Note:** Replace `C:\Path\To\telegram-device-manager` with your actual project path.

2. **Schedule it**
    - Open **Task Scheduler**
    - Click **Create Task**
    - Under **General** tab:
        - Name: `TelegramBot`
        - Check **Run whether user is logged on or not**
    - Go to **Triggers** → **New** → Begin the task: **At startup**
    - Go to **Actions** → **New** → Program/script:
        - `C:\Path\To\telegram-device-manager\start_bot.bat`
    - Click OK, then right-click the task and **Run** to test it.

> 💡 **Tip:** To restart automatically if it stops, you can also use “Repeat task every 5 minutes for a duration of indefinitely” under the **Triggers** tab.

---

## 🔧 Configuration

### Device Configuration Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `ip` | Yes | Device IP address | `192.168.1.100` |
| `mac` | Yes | MAC address for WOL | `AA:BB:CC:DD:EE:FF` |
| `os` | Yes | Operating system | `windows`, `linux`, `macos` |
| `user` | Yes | SSH username | `admin` |
| `port` | No | SSH port (default: 22) | `22` |
| `ssh_key` | No | Path to SSH private key | `/home/user/.ssh/id_rsa` |

### SSH Setup

For shutdown/restart commands to work, configure passwordless SSH:

**Linux/macOS:**

```bash
# Generate SSH key (if you don't have one)
ssh-keygen -t rsa -b 4096

# Copy key to remote device
ssh-copy-id user@device-ip

# Configure sudoers for passwordless shutdown
sudo visudo
# Add: yourusername ALL=(ALL) NOPASSWD: /sbin/shutdown, /sbin/reboot
```

**Windows:**

1. Install OpenSSH Server
2. Configure SSH key authentication
3. Ensure user has shutdown privileges

## 📱 Usage

### Basic Commands

- `/start` - Initialize the bot (first time only)
- `/menu` - Show device control panel
- `/help` - List all available commands
- `/list` - Show all configured devices
- `/add_device` - Add a new device interactively
- `/remove_device` - Remove a device

### Device Commands

For each device, you can use:

- `/wake_devicename` - Wake device via WOL
- `/shutdown_devicename` - Shutdown device
- `/restart_devicename` - Restart device
- `/status_devicename` - Check device status
- `/sleep_devicename` - Sleep device (Windows only)

### Interactive Menu

The bot provides an interactive menu with buttons:

```
[➕] [➖] [📋]
━━━━━━━━━━━━
Windows-PC
[🟢] [🛑] [🔄] [📊] [💤]
Ubuntu-Server
[🟢] [🛑] [🔄] [📊]
```

- ➕ - Add new device
- ➖ - Remove device
- 📋 - List all devices
- 🟢 - Wake device
- 🛑 - Shutdown device
- 🔄 - Restart device
- 📊 - Check status
- 💤 - Sleep (Windows only)

## 🔒 Security

- **User Authentication**: Only authorized Telegram User IDs can use the bot
- **SSH Keys**: Recommended for secure authentication
- **Environment Variables**: Sensitive data stored in `.env` (not committed to git)
- **Sudo Configuration**: Limit passwordless sudo to specific commands only

## 🛠️ Troubleshooting

### Bot doesn't respond

- Check if bot token is correct in `.env`
- Verify your User ID is in `AUTHORIZED_USER_IDS`
- Ensure bot is running without errors

### Wake-on-LAN not working

- Verify MAC address is correct
- Enable WOL in device BIOS/UEFI
- Check if device supports WOL
- Ensure device is on the same network

### SSH commands fail

- Test SSH connection manually: `ssh user@device-ip`
- Verify SSH key permissions (600 for private key)
- Check sudoers configuration for passwordless commands
- Ensure SSH service is running on target device

### Device doesn't wake up in time

- Adjust timeout in code (default: 60 seconds)
- Some devices take longer to boot
- Check network latency

## 📦 Dependencies

```
python-telegram-bot>=20.0
wakeonlan>=3.0.0
python-dotenv>=1.0.0
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/Tupu4545/WakeOnLan/blob/main/LICENSE) file for details.

## ⚠️ Disclaimer

This bot provides remote access to power management functions. Use responsibly and ensure proper security measures are in place. The authors are not responsible for any misuse or damage caused by this software.

## 🙏 Acknowledgments

- [python-telegram-bot](https://github.com/python-telegram-bot/python-telegram-bot) - Telegram Bot API wrapper
- [wakeonlan](https://github.com/remcohaszing/pywakeonlan) - Wake-on-LAN implementation

## 📧 Support

If you encounter any issues or have questions, feel free to dm me on telegram [@tupu4545](t.me/tupu4545) please [open an issue](https://github.com/Tupu4545/WakeOnLan/issues) on GitHub.

---

Made with ❤️ for remote device management

---
