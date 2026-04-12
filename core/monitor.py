"""Background device monitoring and stats refresh."""

import asyncio
import logging
import urllib.request
from typing import Callable, List, Optional

from core.devices import ConfigManager
from core.executor import CommandExecutor
from core.state import StateManager

logger = logging.getLogger(__name__)


class DeviceMonitor:
    """
    Background task that periodically checks all devices,
    updates state, and triggers UI refreshes on both platforms.
    
    Uses check_device_status() (ping + SSH fallback) for accurate
    detection of devices that may block ICMP (e.g. Windows Firewall).
    Checks all devices concurrently via asyncio.gather() for speed.
    """

    def __init__(self, config: ConfigManager, executor: CommandExecutor,
                 state: StateManager):
        self.config = config
        self.executor = executor
        self.state = state
        self._refresh_callbacks: List[Callable] = []
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def add_refresh_callback(self, callback: Callable):
        """Register a callback to be called after each monitoring cycle.
        
        Callbacks should be async functions that update the stats
        message on their respective platform (Telegram/Discord).
        """
        self._refresh_callbacks.append(callback)

    async def start(self):
        """Start the background monitoring loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info(f"Device monitor started (interval: {self.config.monitor_interval}s)")

    async def stop(self):
        """Stop the background monitoring loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Device monitor stopped")

    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self.check_all_devices()
                await self.check_failover_status()
                await self._notify_refresh()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor cycle error: {e}")

            try:
                await asyncio.sleep(self.config.monitor_interval)
            except asyncio.CancelledError:
                break

    async def check_all_devices(self):
        """Check all configured devices concurrently using ping + SSH fallback.
        
        Uses check_device_status() instead of bare ping to handle devices
        that block ICMP (Windows Firewall, etc.). Results are batched into
        a single state save for efficiency.
        """
        if not self.config.devices:
            return

        async def _check_one(name: str):
            """Check a single device and return (name, online)."""
            device = self.config.devices[name]
            try:
                online = await self.executor.check_device_status(device, timeout=5)
                return name, online
            except Exception as e:
                logger.debug(f"Failed to check {name}: {e}")
                return name, False

        # Run all checks concurrently
        tasks = [_check_one(name) for name in self.config.devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Batch update state — single save at the end
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Device check exception: {result}")
                continue
            name, online = result
            self.state.update_device_status(name, online, save=False)
        self.state.save()

    async def check_single_device(self, device_name: str) -> bool:
        """Check a single device using ping + SSH fallback. Returns online status."""
        device = self.config.devices.get(device_name)
        if not device:
            return False
        online = await self.executor.check_device_status(device, timeout=5)
        self.state.update_device_status(device_name, online)
        return online

    async def check_failover_status(self):
        """Check if the peer node heartbeat is reachable."""
        if not self.config.failover_enabled or not self.config.peer_ip:
            return
        try:
            loop = asyncio.get_event_loop()
            alive = await loop.run_in_executor(None, self._check_heartbeat)
            # Store in bot_info for display
            info = self.state.get_bot_info()
            info["primary_reachable"] = alive
            self.state.state["bot_info"] = info
            self.state.save()
        except Exception as e:
            logger.debug(f"Heartbeat check error: {e}")

    def _check_heartbeat(self) -> bool:
        """Synchronous heartbeat check."""
        try:
            url = f"http://{self.config.peer_ip}:{self.config.heartbeat_port}"
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception:
            return False

    async def _notify_refresh(self):
        """Call all registered refresh callbacks."""
        for callback in self._refresh_callbacks:
            try:
                await callback()
            except Exception as e:
                logger.error(f"Refresh callback error: {e}")
