"""Device configuration and management."""

import os
import json
import socket
import logging
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, field

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


@dataclass
class Device:
    """Represents a managed network device."""
    name: str
    ip: str
    mac: str
    os: str
    user: str
    ssh_key: Optional[str] = None
    port: int = 22
    wol_capable: bool = True
    ssh_capable: bool = True

    def to_dict(self) -> dict:
        return {
            'ip': self.ip,
            'mac': self.mac,
            'os': self.os,
            'user': self.user,
            'ssh_key': self.ssh_key,
            'port': self.port,
            'wol_capable': self.wol_capable,
            'ssh_capable': self.ssh_capable
        }


class ConfigManager:
    """Loads environment config and manages devices.json."""

    def __init__(self, devices_file: str = "devices.json"):
        self.devices_file = Path(devices_file)
        self.devices: Dict[str, Device] = {}
        # Telegram
        self.telegram_token: str = ""
        self.telegram_authorized_users: List[int] = []
        # Discord
        self.discord_token: str = ""
        self.discord_authorized_users: List[int] = []
        self.discord_channel_id: int = 0
        # Failover
        self.failover_enabled: bool = True
        self.is_primary: bool = True
        self.peer_ip: str = ""  # secondary IP if primary, primary IP if backup
        self.heartbeat_port: int = 12345
        self.monitor_interval: int = 30

    @property
    def node_name(self) -> str:
        """Derive node name from system hostname."""
        return socket.gethostname()

    @property
    def node_role(self) -> str:
        """Return 'primary' or 'backup' based on is_primary flag."""
        return "primary" if self.is_primary else "backup"

    @property
    def telegram_enabled(self) -> bool:
        """Telegram is enabled if a token is present."""
        return bool(self.telegram_token)

    @property
    def discord_enabled(self) -> bool:
        """Discord is enabled if a token is present."""
        return bool(self.discord_token)

    def load_config(self):
        """Load all configuration from .env and devices.json."""
        load_dotenv()

        # Telegram
        self.telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        tg_users = os.getenv("TELEGRAM_AUTHORIZED_USERS", "")
        if tg_users:
            self.telegram_authorized_users = [
                int(uid.strip()) for uid in tg_users.split(",") if uid.strip()
            ]

        # Discord — enabled if token is present
        self.discord_token = os.getenv("DISCORD_BOT_TOKEN", "")
        dc_users = os.getenv("DISCORD_AUTHORIZED_USERS", "")
        if dc_users:
            self.discord_authorized_users = [
                int(uid.strip()) for uid in dc_users.split(",") if uid.strip()
            ]
        channel_id = os.getenv("DISCORD_CHANNEL_ID", "")
        self.discord_channel_id = int(channel_id) if channel_id else 0

        # Failover
        self.failover_enabled = os.getenv("FAILOVER_ENABLED", "yes").lower() in ("yes", "true", "1")
        self.is_primary = os.getenv("PRIMARY_DEVICE", "yes").lower() in ("yes", "true", "1")
        if self.is_primary:
            self.peer_ip = os.getenv("SECONDARY_IP", "")
        else:
            self.peer_ip = os.getenv("PRIMARY_IP", "")
        self.heartbeat_port = int(os.getenv("HEARTBEAT_PORT", "12345"))
        self.monitor_interval = int(os.getenv("MONITOR_INTERVAL", "30"))

        # Devices
        if self.devices_file.exists():
            self.reload_devices()

    def reload_devices(self):
        """Reload only the devices from devices.json without re-evaluating .env."""
        if not self.devices_file.exists():
            return
            
        try:
            with open(self.devices_file, "r") as f:
                devices_data = json.load(f)
                
            self.devices.clear()
            for name, config in devices_data.items():
                self.devices[name] = Device(
                    name=name,
                    ip=config['ip'],
                    mac=config.get('mac', ''),
                    os=config.get('os', 'linux'),
                    user=config.get('user', ''),
                    ssh_key=config.get('ssh_key'),
                    port=config.get('port', 22),
                    wol_capable=config.get('wol_capable', True),
                    ssh_capable=config.get('ssh_capable', True)
                )
            logger.info(f"Loaded {len(self.devices)} devices from {self.devices_file}")
        except Exception as e:
            logger.error(f"Failed to reload devices: {e}")

    def add_device(self, device: Device):
        """Add a device and persist to disk."""
        self.devices[device.name] = device
        self._save_devices()
        logger.info(f"Added device: {device.name}")

    def remove_device(self, device_name: str) -> bool:
        """Remove a device and persist to disk."""
        if device_name in self.devices:
            del self.devices[device_name]
            self._save_devices()
            logger.info(f"Removed device: {device_name}")
            return True
        return False

    def _save_devices(self):
        """Write current devices to devices.json."""
        with open(self.devices_file, 'w') as f:
            json.dump(
                {n: d.to_dict() for n, d in self.devices.items()},
                f, indent=2
            )
