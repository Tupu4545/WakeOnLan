"""
Failover Manager — Active-Passive heartbeat system.

Primary node: broadcasts a heartbeat on an HTTP port + runs the bot.
Backup node: monitors the heartbeat and takes over if primary goes down.

This module is integrated into the bot process (no subprocess spawning).
"""

import asyncio
import logging
import signal
import urllib.request
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class HeartbeatServer:
    """Simple HTTP server that responds 200 OK and serves config files."""

    def __init__(self, port: int, config, state):
        self.port = port
        self.config = config
        self.state = state
        self._server = None
        self._thread = None

    def start(self):
        """Start the heartbeat server in a background thread."""
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/devices.json':
                    try:
                        with open(parent.config.devices_file, 'rb') as f:
                            content = f.read()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    except Exception as e:
                        logger.error(f"Failed to serve devices.json: {e}")
                        self.send_response(404)
                        self.end_headers()
                        return
                
                if self.path == '/message_state.json':
                    try:
                        with open(parent.state.state_file, 'rb') as f:
                            content = f.read()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(content)
                        return
                    except Exception as e:
                        logger.error(f"Failed to serve message_state.json: {e}")
                        self.send_response(404)
                        self.end_headers()
                        return

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, format, *args):
                pass  # Suppress request logs

        class ReusableServer(HTTPServer):
            allow_reuse_address = True

        self._server = ReusableServer(('0.0.0.0', self.port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()
        logger.info(f"Heartbeat server started on port {self.port}")

    def stop(self):
        """Stop the heartbeat server."""
        if self._server:
            self._server.shutdown()
            logger.info("Heartbeat server stopped")


class FailoverWatcher:
    """
    Monitors the primary node's heartbeat.
    
    If the heartbeat fails `fail_threshold` consecutive times,
    calls `on_primary_down()`. When the primary comes back,
    calls `on_primary_up()`.
    """

    def __init__(self, primary_ip: str, port: int, config, state,
                 check_interval: int = 10, fail_threshold: int = 3):
        self.primary_ip = primary_ip
        self.port = port
        self.config = config
        self.state = state
        self.check_interval = check_interval
        self.fail_threshold = fail_threshold
        self._consecutive_failures = 0
        self._primary_is_down = False
        self._running = False
        self._task = None
        self.on_primary_down = None  # async callback
        self.on_primary_up = None    # async callback

    async def start(self):
        """Start watching the primary."""
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info(
            f"Failover watcher started (primary={self.primary_ip}:{self.port}, "
            f"interval={self.check_interval}s, threshold={self.fail_threshold})"
        )

    async def stop(self):
        """Stop watching."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Failover watcher stopped")

    async def _watch_loop(self):
        """Main watch loop."""
        while self._running:
            try:
                alive = await self._check_heartbeat()

                if alive:
                    self._consecutive_failures = 0
                    if self._primary_is_down:
                        self._primary_is_down = False
                        logger.info("Primary is back online!")
                        if self.on_primary_up:
                            await self.on_primary_up()
                    
                    # Sync config from primary continuously while it's alive
                    await self._sync_files()
                else:
                    self._consecutive_failures += 1
                    logger.debug(
                        f"Heartbeat fail {self._consecutive_failures}/{self.fail_threshold}"
                    )
                    if (self._consecutive_failures >= self.fail_threshold
                            and not self._primary_is_down):
                        self._primary_is_down = True
                        logger.warning("Primary is DOWN! Taking over...")
                        if self.on_primary_down:
                            await self.on_primary_down()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Watcher error: {e}")

            try:
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break

    async def _check_heartbeat(self) -> bool:
        """Check if the primary's heartbeat server is responding."""
        loop = asyncio.get_event_loop()
        try:
            url = f"http://{self.primary_ip}:{self.port}"
            await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(url, timeout=3)
            )
            return True
        except Exception:
            return False

    async def _sync_files(self):
        """Fetch json files from primary and compare before saving to prevent SD card wear."""
        loop = asyncio.get_event_loop()
        
        for path, file_path, reload_func in [
            ('/devices.json', self.config.devices_file, self.config.reload_devices),
            ('/message_state.json', self.state.state_file, self.state.load)
        ]:
            try:
                url = f"http://{self.primary_ip}:{self.port}{path}"
                def fetch():
                    with urllib.request.urlopen(url, timeout=3) as response:
                        return response.read()
                
                content = await loop.run_in_executor(None, fetch)
                content_str = content.decode('utf-8')
                
                has_changed = True
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        local_content = f.read()
                    if local_content == content_str:
                        has_changed = False
                except Exception:
                    pass  # File likely doesn't exist, so has_changed stays True
                    
                if has_changed:
                    logger.info(f"Syncing {file_path} from primary (Content changed)...")
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content_str)
                    reload_func()
                    
            except Exception as e:
                # logger.debug(f"Failed to sync {path} from primary: {e}")
                pass


class GracefulShutdown:
    """Handle SIGTERM/SIGINT for clean shutdown."""

    def __init__(self):
        self._shutdown_event = asyncio.Event()
        self._callbacks = []

    def register(self, callback):
        """Register an async callback to run on shutdown."""
        self._callbacks.append(callback)

    def setup(self, loop):
        """Register signal handlers."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._trigger)
        logger.info("Graceful shutdown handlers registered")

    def _trigger(self):
        """Signal received, trigger shutdown."""
        logger.info("Shutdown signal received")
        self._shutdown_event.set()

    async def wait(self):
        """Wait for shutdown signal."""
        await self._shutdown_event.wait()

    async def execute(self):
        """Run all shutdown callbacks."""
        logger.info("Running shutdown callbacks...")
        for cb in self._callbacks:
            try:
                await cb()
            except Exception as e:
                logger.error(f"Shutdown callback error: {e}")
        logger.info("Shutdown complete")
