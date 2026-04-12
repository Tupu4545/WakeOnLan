"""Command execution: ping, SSH, Wake-on-LAN."""

import asyncio
import platform
import logging
from typing import Tuple

from wakeonlan import send_magic_packet

from core.devices import Device

logger = logging.getLogger(__name__)

# Detect OS once at import time
_SYSTEM = platform.system().lower()


class CommandExecutor:
    """Handles device commands: ping, SSH, and WoL."""

    @staticmethod
    async def ping_device(ip: str, timeout: int = 2) -> bool:
        """Ping a device and return True if reachable.
        
        Works correctly on macOS (-t for seconds), Linux (-W for seconds),
        and Windows (-w for milliseconds).
        Default timeout: 2 seconds (fast for local network).
        """
        if _SYSTEM == 'windows':
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        elif _SYSTEM == 'darwin':
            # macOS: -t is timeout in seconds, -W is in milliseconds
            cmd = ["ping", "-c", "1", "-t", str(timeout), ip]
        else:
            # Linux: -W is deadline in seconds
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            # Also enforce a hard timeout in case ping hangs
            try:
                return await asyncio.wait_for(process.wait(), timeout=timeout + 2) == 0
            except asyncio.TimeoutError:
                process.kill()
                return False
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
            return False

    @staticmethod
    async def check_device_status(device: Device, timeout: int = 5) -> bool:
        """Check device status: ping first (2s), SSH fallback if capable.
        Total timeout capped at `timeout` seconds (default 5)."""
        # Try ping first — 2 seconds max
        ping_timeout = min(timeout, 2)
        if await CommandExecutor.ping_device(device.ip, timeout=ping_timeout):
            return True
        # SSH fallback only if device supports it
        if device.ssh_capable and device.user:
            remaining = max(timeout - ping_timeout, 2)
            ok, _ = await CommandExecutor.ssh_command(
                device, "echo ok", timeout=remaining
            )
            return ok
        return False

    @staticmethod
    async def ssh_command(device: Device, command: str, timeout: int = 5) -> Tuple[bool, str]:
        """Execute a command on a device via SSH."""
        ssh_cmd = [
            "ssh",
            "-o", f"ConnectTimeout={timeout}",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
        ]
        if device.ssh_key:
            ssh_cmd.extend(["-i", str(device.ssh_key)])
        if device.port != 22:
            ssh_cmd.extend(["-p", str(device.port)])
        ssh_cmd.extend([f"{device.user}@{device.ip}", command])

        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout + 2
                )
            except asyncio.TimeoutError:
                process.kill()
                return False, "SSH timed out"
            output = (stdout.decode() if stdout else stderr.decode()).strip()
            return process.returncode == 0, output
        except Exception as e:
            logger.error(f"SSH command failed for {device.name}: {e}")
            return False, str(e)

    @staticmethod
    async def wake_device(mac: str):
        """Send a Wake-on-LAN magic packet."""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, send_magic_packet, mac)
        logger.info(f"WOL sent to {mac}")

    @staticmethod
    def get_shutdown_command(device: Device) -> str:
        """Get the OS-appropriate shutdown command."""
        if device.os.lower() == 'windows':
            return "shutdown /s /t 0"
        return "sudo -n /sbin/shutdown -h now"

    @staticmethod
    def get_restart_command(device: Device) -> str:
        """Get the OS-appropriate restart command."""
        if device.os.lower() == 'windows':
            return "shutdown /r /t 0"
        return "sudo -n reboot now"

    @staticmethod
    def get_sleep_command(device: Device) -> str:
        """Get the OS-appropriate sleep command."""
        if device.os.lower() == 'windows':
            return "rundll32.exe powrprof.dll,SetSuspendState 0,1,0"
        elif device.os.lower() == 'macos':
            return "sudo pmset sleepnow"
        elif device.os.lower() == 'linux':
            return "sudo -n systemctl suspend"
        return ""
