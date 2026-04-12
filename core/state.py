"""Persistent state management for message IDs and device stats."""

import json
import os
import logging
import fcntl
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

# India Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))

# Timezone-aware UTC helper
def utcnow() -> datetime:
    return datetime.now(timezone.utc)

def format_time(dt: datetime) -> str:
    """Format a datetime for display in 24h IST."""
    if dt is None:
        return "Never"
    ist_time = dt.astimezone(IST)
    return ist_time.strftime("%b %d, %H:%M IST")

def format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration."""
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours = int(minutes // 60)
    remaining_min = minutes % 60
    if hours < 24:
        return f"{hours}h {remaining_min}m"
    days = int(hours // 24)
    remaining_hrs = hours % 24
    return f"{days}d {remaining_hrs}h {remaining_min}m"


class StateManager:
    """
    Manages persistent state stored in message_state.json.
    
    State structure:
    {
        "telegram": {
            "<user_id>": {
                "chat_id": int,
                "stats_msg_id": int,
                "action_msg_id": int,
                "panel_msg_id": int
            }
        },
        "discord": {
            "channel_id": int,
            "stats_msg_id": int,
            "action_msg_id": int,
            "panel_msg_id": int
        },
        "discord_users": {
            "<user_id>": {
                "dm_channel_id": int,
                "stats_msg_id": int,
                "action_msg_id": int,
                "panel_msg_id": int
            }
        },
        "device_stats": {
            "<device_name>": {
                "online": bool,
                "last_checked": str (ISO),
                "online_since": str (ISO) or null,
                "last_seen": str (ISO) or null
            }
        },
        "bot_info": {
            "node_name": str,
            "role": str,
            "started_at": str (ISO)
        }
    }
    """

    def __init__(self, state_file: str = "message_state.json"):
        self.state_file = state_file
        self.state: Dict[str, Any] = {
            "telegram": {},
            "discord": {},
            "discord_users": {},
            "device_stats": {},
            "bot_info": {}
        }
        self.load()

    def load(self):
        """Load state from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    # Merge with defaults to handle missing keys
                    self.state["telegram"] = data.get("telegram", {})
                    self.state["discord"] = data.get("discord", {})
                    self.state["discord_users"] = data.get("discord_users", {})
                    self.state["device_stats"] = data.get("device_stats", {})
                    self.state["bot_info"] = data.get("bot_info", {})
                logger.info(f"Loaded state from {self.state_file}")
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")

    def save(self):
        """Save state to disk with file locking."""
        try:
            with open(self.state_file, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(self.state, f, indent=2, default=str)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    # ── Telegram message IDs ──

    def get_telegram_user(self, user_id: int) -> Optional[dict]:
        """Get stored message IDs for a Telegram user."""
        return self.state["telegram"].get(str(user_id))

    def set_telegram_user(self, user_id: int, chat_id: int,
                          stats_msg_id: int, action_msg_id: int,
                          panel_msg_id: int):
        """Store message IDs for a Telegram user."""
        self.state["telegram"][str(user_id)] = {
            "chat_id": chat_id,
            "stats_msg_id": stats_msg_id,
            "action_msg_id": action_msg_id,
            "panel_msg_id": panel_msg_id
        }
        self.save()

    def update_telegram_msg(self, user_id: int, key: str, msg_id: int):
        """Update a single message ID for a Telegram user."""
        uid = str(user_id)
        if uid in self.state["telegram"]:
            self.state["telegram"][uid][key] = msg_id
            self.save()

    def clear_telegram_user(self, user_id: int):
        """Clear stored message IDs for a Telegram user."""
        uid = str(user_id)
        if uid in self.state["telegram"]:
            del self.state["telegram"][uid]
            self.save()

    # ── Discord channel message IDs ──

    def get_discord(self) -> Optional[dict]:
        """Get stored Discord channel message IDs."""
        return self.state["discord"] if self.state["discord"] else None

    def set_discord(self, channel_id: int, stats_msg_id: int,
                    action_msg_id: int, panel_msg_id: int):
        """Store Discord channel message IDs."""
        self.state["discord"] = {
            "channel_id": channel_id,
            "stats_msg_id": stats_msg_id,
            "action_msg_id": action_msg_id,
            "panel_msg_id": panel_msg_id
        }
        self.save()

    def update_discord_msg(self, key: str, msg_id: int):
        """Update a single Discord channel message ID."""
        if self.state["discord"]:
            self.state["discord"][key] = msg_id
            self.save()

    # ── Discord per-user DM message IDs ──

    def get_discord_user(self, user_id: int) -> Optional[dict]:
        """Get stored DM message IDs for a Discord user."""
        return self.state["discord_users"].get(str(user_id))

    def set_discord_user(self, user_id: int, dm_channel_id: int,
                         stats_msg_id: int, action_msg_id: int,
                         panel_msg_id: int):
        """Store DM message IDs for a Discord user."""
        self.state["discord_users"][str(user_id)] = {
            "dm_channel_id": dm_channel_id,
            "stats_msg_id": stats_msg_id,
            "action_msg_id": action_msg_id,
            "panel_msg_id": panel_msg_id
        }
        self.save()

    def update_discord_user_msg(self, user_id: int, key: str, msg_id: int):
        """Update a single DM message ID for a Discord user."""
        uid = str(user_id)
        if uid in self.state["discord_users"]:
            self.state["discord_users"][uid][key] = msg_id
            self.save()

    def clear_discord_user(self, user_id: int):
        """Clear stored DM message IDs for a Discord user."""
        uid = str(user_id)
        if uid in self.state["discord_users"]:
            del self.state["discord_users"][uid]
            self.save()

    # ── Device stats ──

    def get_device_stats(self, device_name: str) -> Optional[dict]:
        """Get stats for a device."""
        return self.state["device_stats"].get(device_name)

    def get_all_device_stats(self) -> Dict[str, dict]:
        """Get stats for all devices."""
        return self.state["device_stats"]

    def update_device_status(self, device_name: str, online: bool, save: bool = True):
        """Update a device's online status with timestamps.
        
        Args:
            device_name: Name of the device.
            online: Whether the device is currently online.
            save: Whether to persist to disk immediately. Set False for
                  batch updates (call save() manually after all updates).
        """
        now = utcnow().isoformat()
        stats = self.state["device_stats"].get(device_name, {
            "online": False,
            "last_checked": None,
            "online_since": None,
            "last_seen": None
        })

        was_online = stats.get("online", False)
        stats["online"] = online
        stats["last_checked"] = now

        if online:
            stats["last_seen"] = now
            if not was_online:
                # Just came online
                stats["online_since"] = now
        else:
            if was_online:
                # Just went offline
                stats["online_since"] = None

        self.state["device_stats"][device_name] = stats
        if save:
            self.save()

    def remove_device_stats(self, device_name: str):
        """Remove stats for a device."""
        if device_name in self.state["device_stats"]:
            del self.state["device_stats"][device_name]
            self.save()

    # ── Bot info ──

    def set_bot_info(self, node_name: str, role: str, failover_enabled: bool):
        """Set bot instance info."""
        self.state["bot_info"] = {
            "node_name": node_name,
            "role": role,
            "failover_enabled": failover_enabled,
            "started_at": utcnow().isoformat()
        }
        self.save()

    def get_bot_info(self) -> dict:
        """Get bot instance info."""
        return self.state["bot_info"]

    def get_bot_uptime(self) -> str:
        """Get formatted bot uptime."""
        info = self.state["bot_info"]
        if not info or "started_at" not in info:
            return "Unknown"
        started = datetime.fromisoformat(info["started_at"])
        delta = (utcnow() - started).total_seconds()
        return format_duration(delta)
