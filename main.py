"""
WakeOnLan Bot — Main Entry Point

Orchestrates:
  - Telegram bot (if enabled)
  - Discord bot (if enabled)
  - Background device monitor
  - Failover heartbeat (primary) or watcher (backup)
  - Graceful shutdown on SIGTERM/SIGINT
"""

import sys
import asyncio
import logging
from logging.handlers import RotatingFileHandler

# Configure logging before anything else
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        RotatingFileHandler('bot.log', maxBytes=5*1024*1024, backupCount=3)
    ]
)
logger = logging.getLogger(__name__)

from core.devices import ConfigManager
from core.executor import CommandExecutor
from core.state import StateManager
from core.monitor import DeviceMonitor
from failover import HeartbeatServer, FailoverWatcher, GracefulShutdown


async def main():
    # ── Load config ──
    config = ConfigManager()
    config.load_config()

    if not config.telegram_enabled and not config.discord_enabled:
        logger.error("Neither TELEGRAM_BOT_TOKEN nor DISCORD_BOT_TOKEN is set. Nothing to start.")
        sys.exit(1)

    # ── Shared components ──
    executor = CommandExecutor()
    state = StateManager()
    state.set_bot_info(config.node_name, config.node_role, config.failover_enabled)

    # ── Device monitor ──
    monitor = DeviceMonitor(config, executor, state)

    # ── Telegram bot ──
    tg_bot = None
    if config.telegram_enabled:
        from bot import TelegramBot
        tg_bot = TelegramBot(config, executor, state)
        monitor.add_refresh_callback(tg_bot.on_monitor_refresh)
        logger.info("Telegram bot enabled")

    # ── Discord bot ──
    dc_bot = None
    if config.discord_enabled:
        try:
            from discord_bot import DiscordBot
            dc_bot = DiscordBot(config, executor, state)
            monitor.add_refresh_callback(dc_bot.on_monitor_refresh)
            logger.info("Discord bot enabled")
        except ImportError as e:
            logger.warning(f"Discord bot disabled (discord.py not installed): {e}")

    # ── Failover ──
    heartbeat = None
    watcher = None

    if config.failover_enabled:
        if config.is_primary:
            heartbeat = HeartbeatServer(config.heartbeat_port, config, state)
            heartbeat.start()
            logger.info(f"Running as PRIMARY ({config.node_name})")
        else:
            watcher = FailoverWatcher(
                config.peer_ip, config.heartbeat_port, config, state,
                check_interval=10, fail_threshold=3
            )
            logger.info(f"Running as BACKUP ({config.node_name})")
    else:
        logger.info(f"Running standalone (Failover disabled)")

    _bot_tasks = []

    async def start_bots():
        logger.info("Starting bots...")
        if tg_bot:
            try:
                await tg_bot.start_polling()
            except Exception as e:
                logger.error(f"Failed to start Telegram bot: {e}")
        if dc_bot:
            t = asyncio.create_task(dc_bot.start())
            _bot_tasks.append(t)

    async def stop_bots():
        logger.info("Stopping bots...")
        if tg_bot:
            try:
                await tg_bot.stop_polling()
            except Exception as e:
                logger.error(f"Failed to stop Telegram bot: {e}")
        if dc_bot:
            try:
                await dc_bot.stop()
            except Exception as e:
                logger.error(f"Failed to stop Discord bot: {e}")
        if _bot_tasks:
            await asyncio.gather(*_bot_tasks, return_exceptions=True)
            _bot_tasks.clear()

    if watcher:
        watcher.on_primary_down = start_bots
        watcher.on_primary_up = stop_bots

    # ── Graceful shutdown ──
    shutdown = GracefulShutdown()
    shutdown.register(monitor.stop)
    shutdown.register(stop_bots)
    if heartbeat:
        # Wrap stop in coroutine so GracefulShutdown can await it
        shutdown.register(lambda: asyncio.to_thread(heartbeat.stop))
    if watcher:
        shutdown.register(watcher.stop)

    # ── Start everything ──
    try:
        loop = asyncio.get_event_loop()
        shutdown.setup(loop)
    except Exception:
        pass  # Signal handlers may not work on all platforms

    logger.info("=" * 50)
    logger.info(f"WakeOnLan Bot v2 starting")
    logger.info(f"Node: {config.node_name} | Role: {config.node_role}")
    logger.info(f"Devices: {len(config.devices)}")
    logger.info(f"Telegram: {'enabled' if tg_bot else 'disabled'}")
    logger.info(f"Discord: {'enabled' if dc_bot else 'disabled'}")
    logger.info("=" * 50)

    # Start monitor
    await monitor.start()

    # Start failover watcher (backup nodes)
    if watcher:
        await watcher.start()
    else:
        # Standalone or primary node starts bots immediately
        await start_bots()

    try:
        await shutdown.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        await shutdown.execute()
        logger.info("Bot shut down cleanly")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted")
