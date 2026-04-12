"""
Telegram Bot — 3-message persistent UI for Wake-on-LAN device management.

Messages (top → bottom):
  1. Control Panel    — inline keyboard with device buttons
  2. Stats Dashboard  — auto-refreshes, shows device/bot/failover status
  3. Action Log       — updates in-place when buttons are pressed (bottom)
"""

import re
import asyncio
import ipaddress
import logging
from datetime import datetime, timezone

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, ContextTypes,
    CallbackQueryHandler, ConversationHandler, MessageHandler, filters
)

from core.devices import Device, ConfigManager
from core.executor import CommandExecutor
from core.state import StateManager, format_time, format_duration, utcnow

logger = logging.getLogger(__name__)

# Conversation states for add-device flow
ADD_NAME, ADD_IP, ADD_OS, ADD_WOL, ADD_MAC, ADD_SSH, ADD_USER = range(7)


class TelegramBot:
    """Telegram bot with 3-message persistent UI."""

    def __init__(self, config: ConfigManager, executor: CommandExecutor,
                 state: StateManager):
        self.config = config
        self.executor = executor
        self.state = state
        self.app = None

    # ─── Message Builders ───────────────────────────────────────

    def build_stats_text(self) -> str:
        """Build a compact stats dashboard — just devices + status emoji."""
        from core.state import IST
        now_ist = utcnow().astimezone(IST)
        time_str = now_ist.strftime("%H:%M:%S IST")

        lines = [f"📊 Devices  ·  {time_str}", "━━━━━━━━━━━━━━━━━━━━━"]

        if self.config.devices:
            for name in self.config.devices:
                stats = self.state.get_device_stats(name)
                if stats and stats.get("online"):
                    icon = "🟢"
                elif stats and stats.get("last_checked"):
                    icon = "🔴"
                else:
                    icon = "⚪"
                lines.append(f"{icon} {name}")
        else:
            lines.append("No devices configured")

        return "\n".join(lines)

    def build_action_text(self, text: str = None) -> str:
        """Build the action log message."""
        if text:
            return text
        return "📋 Ready"

    def build_panel_keyboard(self) -> InlineKeyboardMarkup:
        """Build the control panel inline keyboard with dynamic buttons."""
        keyboard = [
            [
                InlineKeyboardButton("➕ Add", callback_data="add_device"),
                InlineKeyboardButton("🗑️ Remove", callback_data="remove_device_menu"),
                InlineKeyboardButton("🔄 Refresh", callback_data="refresh_stats"),
            ]
        ]

        if self.config.devices:
            keyboard.append([InlineKeyboardButton("━━━━━━━━━━━━━━━━━━━━", callback_data="noop")])
            for name, device in self.config.devices.items():
                # Device name is clickable — triggers status check
                keyboard.append([InlineKeyboardButton(f"  {name}  ", callback_data=f"status:{name}")])
                row = []
                if device.wol_capable:
                    row.append(InlineKeyboardButton("🟢", callback_data=f"wake:{name}"))
                if device.ssh_capable:
                    row.append(InlineKeyboardButton("🛑", callback_data=f"shutdown:{name}"))
                    row.append(InlineKeyboardButton("🔄", callback_data=f"restart:{name}"))
                    row.append(InlineKeyboardButton("💤", callback_data=f"sleep:{name}"))
                if row:
                    keyboard.append(row)

        return InlineKeyboardMarkup(keyboard)

    # ─── Message Management ─────────────────────────────────────

    async def _edit_or_resend(self, chat_id: int, msg_id: int, text: str,
                              context: ContextTypes.DEFAULT_TYPE,
                              reply_markup=None) -> int:
        """Try to edit a message. If it doesn't exist, send a new one.
        Returns the (possibly new) message ID."""
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, message_id=msg_id, text=text,
                reply_markup=reply_markup
            )
            return msg_id
        except Exception as e:
            if "Message is not modified" in str(e):
                return msg_id
            logger.debug(f"Edit failed (will resend): {e}")
            msg = await context.bot.send_message(
                chat_id=chat_id, text=text, reply_markup=reply_markup
            )
            return msg.message_id

    async def _delete_safe(self, chat_id: int, message_id: int,
                           context: ContextTypes.DEFAULT_TYPE):
        """Delete a message, ignoring errors."""
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception as e:
            logger.debug(f"Could not delete message {message_id}: {e}")

    async def setup_messages(self, user_id: int, chat_id: int,
                             context: ContextTypes.DEFAULT_TYPE):
        """
        Create or recover the 3 persistent messages.
        
        Order: Panel (top) → Stats (middle) → Action (bottom)
        """
        stored = self.state.get_telegram_user(user_id)

        if stored:
            # Try to reuse existing messages
            try:
                panel_id = await self._edit_or_resend(
                    chat_id, stored["panel_msg_id"],
                    "🎛 Device Control Panel", context,
                    reply_markup=self.build_panel_keyboard()
                )
                stats_id = await self._edit_or_resend(
                    chat_id, stored["stats_msg_id"],
                    self.build_stats_text(), context
                )
                action_id = await self._edit_or_resend(
                    chat_id, stored["action_msg_id"],
                    self.build_action_text(), context
                )
                self.state.set_telegram_user(
                    user_id, chat_id, stats_id, action_id, panel_id
                )
                return
            except Exception as e:
                logger.warning(f"Could not recover messages, creating fresh: {e}")

        # Send fresh messages: Panel → Stats → Action
        panel_msg = await context.bot.send_message(
            chat_id=chat_id, text="🎛 Device Control Panel",
            reply_markup=self.build_panel_keyboard()
        )
        stats_msg = await context.bot.send_message(
            chat_id=chat_id, text=self.build_stats_text()
        )
        action_msg = await context.bot.send_message(
            chat_id=chat_id, text=self.build_action_text()
        )

        self.state.set_telegram_user(
            user_id, chat_id,
            stats_msg.message_id,
            action_msg.message_id,
            panel_msg.message_id
        )

    async def update_stats(self, user_id: int = None, context: ContextTypes.DEFAULT_TYPE = None):
        """Refresh the stats dashboard message for one or all users."""
        text = self.build_stats_text()

        if user_id and context:
            stored = self.state.get_telegram_user(user_id)
            if stored:
                new_id = await self._edit_or_resend(
                    stored["chat_id"], stored["stats_msg_id"], text, context
                )
                if new_id != stored["stats_msg_id"]:
                    self.state.update_telegram_msg(user_id, "stats_msg_id", new_id)
            return

        # Refresh for all users (called by monitor)
        if not self.app:
            return
        text = self.build_stats_text()
        for uid_str, stored in self.state.state["telegram"].items():
            try:
                new_id = await self._edit_or_resend(
                    stored["chat_id"], stored["stats_msg_id"], text,
                    self.app
                )
                if new_id != stored["stats_msg_id"]:
                    self.state.update_telegram_msg(int(uid_str), "stats_msg_id", new_id)
            except Exception as e:
                logger.debug(f"Stats refresh failed for user {uid_str}: {e}")

    async def update_action(self, user_id: int, chat_id: int, text: str,
                            context: ContextTypes.DEFAULT_TYPE,
                            reply_markup=None):
        """Update the action log message (message 2)."""
        stored = self.state.get_telegram_user(user_id)
        if not stored:
            return
        new_id = await self._edit_or_resend(
            chat_id, stored["action_msg_id"], text, context,
            reply_markup=reply_markup
        )
        if new_id != stored["action_msg_id"]:
            self.state.update_telegram_msg(user_id, "action_msg_id", new_id)

    async def update_panel(self, user_id: int, chat_id: int,
                           context: ContextTypes.DEFAULT_TYPE):
        """Refresh the control panel keyboard (message 3)."""
        stored = self.state.get_telegram_user(user_id)
        if not stored:
            return
        new_id = await self._edit_or_resend(
            chat_id, stored["panel_msg_id"],
            "🎛 Device Control Panel", context,
            reply_markup=self.build_panel_keyboard()
        )
        if new_id != stored["panel_msg_id"]:
            self.state.update_telegram_msg(user_id, "panel_msg_id", new_id)

    # ─── Command Handlers ───────────────────────────────────────

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start — create panel only if one doesn't already exist."""
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id

        if user_id not in self.config.telegram_authorized_users:
            return

        # Delete the command message
        await self._delete_safe(chat_id, update.message.message_id, context)

        # If panel already exists, do nothing (prevents loop on restart)
        stored = self.state.get_telegram_user(user_id)
        if stored:
            return

        # No panel exists — create one
        await self.setup_messages(user_id, chat_id, context)

    async def panel_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /panel — force-delete old panel and recreate cleanly."""
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id

        if user_id not in self.config.telegram_authorized_users:
            return

        # Prevent double-processing if /panel is sent rapidly
        lock_key = f"panel_lock_{user_id}"
        if context.bot_data.get(lock_key):
            return
        context.bot_data[lock_key] = True

        try:
            # Delete the command message itself
            await self._delete_safe(chat_id, update.message.message_id, context)

            # Delete stored bot messages only
            stored = self.state.get_telegram_user(user_id)
            if stored:
                for key in ("panel_msg_id", "stats_msg_id", "action_msg_id"):
                    if key in stored:
                        await self._delete_safe(chat_id, stored[key], context)

            self.state.clear_telegram_user(user_id)

            # Create fresh messages
            await self.setup_messages(user_id, chat_id, context)
        finally:
            context.bot_data[lock_key] = False

    # ─── Button Callbacks ───────────────────────────────────────

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline keyboard button presses."""
        query = update.callback_query
        try:
            await query.answer()
        except Exception as e:
            logger.debug(f"Could not answer callback: {e}")

        user_id = query.from_user.id
        chat_id = query.message.chat_id

        if user_id not in self.config.telegram_authorized_users:
            return
        if query.data == "noop":
            return

        # Refresh stats
        if query.data == "refresh_stats":
            await self.update_action(user_id, chat_id, "🔄 Refreshing...", context)
            
            async def _check(n, d):
                return n, await self.executor.check_device_status(d, timeout=5)
            
            results = await asyncio.gather(*[_check(n, d) for n, d in self.config.devices.items()])
            for n, online in results:
                self.state.update_device_status(n, online, save=False)
            self.state.save()
            
            await self.update_stats(user_id, context)
            await self.update_action(user_id, chat_id, "✅ Stats refreshed!", context)
            return

        # Remove device menu
        if query.data == "remove_device_menu":
            if not self.config.devices:
                await self.update_action(
                    user_id, chat_id, "❌ No devices to remove.", context
                )
                return
            kb = [
                [InlineKeyboardButton(f"🗑️ {n}", callback_data=f"remove:{n}")]
                for n in self.config.devices.keys()
            ]
            kb.append([InlineKeyboardButton("❌ Cancel", callback_data="cancel_remove")])
            await self.update_action(
                user_id, chat_id, "Select device to remove:",
                context, reply_markup=InlineKeyboardMarkup(kb)
            )
            return

        if query.data.startswith("remove:") and not query.data.startswith("remove_confirm:"):
            name = query.data.split(":", 1)[1]
            kb = [[
                InlineKeyboardButton("✅ Yes", callback_data=f"remove_confirm:{name}"),
                InlineKeyboardButton("❌ No", callback_data="cancel_remove")
            ]]
            await self.update_action(
                user_id, chat_id, f"⚠️ Remove {name}?",
                context, reply_markup=InlineKeyboardMarkup(kb)
            )
            return

        if query.data.startswith("remove_confirm:"):
            name = query.data.split(":", 1)[1]
            if self.config.remove_device(name):
                self.state.remove_device_stats(name)
                await self.update_action(
                    user_id, chat_id, f"🗑️ {name} removed!", context
                )
                await self.update_panel(user_id, chat_id, context)
                await self.update_stats(user_id, context)
            return

        if query.data == "cancel_remove":
            await self.update_action(
                user_id, chat_id, self.build_action_text(), context
            )
            return

        # Device actions
        try:
            action, name = query.data.split(":", 1)
        except ValueError:
            return

        device = self.config.devices.get(name)
        if not device:
            return

        # Run device action in a background task
        async def run_action():
            try:
                if action == 'wake':
                    await self.update_action(
                        user_id, chat_id,
                        f"🟢 {name}\n📡 Sending WOL packet...", context
                    )
                    await self.executor.wake_device(device.mac)
                    await self.update_action(
                        user_id, chat_id,
                        f"🟢 {name}\n📡 WOL sent, waiting for response...", context
                    )
                    await asyncio.sleep(2)
                    for i in range(12):
                        if await self.executor.ping_device(device.ip):
                            self.state.update_device_status(name, True)
                            await self.update_action(
                                user_id, chat_id,
                                f"✅ {name}\n🟢 ONLINE", context
                            )
                            await self.update_stats(user_id, context)
                            return
                        await self.update_action(
                            user_id, chat_id,
                            f"🟢 {name}\n🔍 Pinging... ({i+1}/12)", context
                        )
                        await asyncio.sleep(5)
                    await self.update_action(
                        user_id, chat_id,
                        f"⚠️ {name}\n❌ Timeout — device did not respond", context
                    )

                elif action == 'status':
                    await self.update_action(
                        user_id, chat_id,
                        f"🔍 {name}\n⏳ Checking...", context
                    )
                    online = await self.executor.check_device_status(device, timeout=5)
                    self.state.update_device_status(name, online)
                    if online:
                        await self.update_action(
                            user_id, chat_id,
                            f"✅ {name}  🟢 Online", context
                        )
                    else:
                        await self.update_action(
                            user_id, chat_id,
                            f"❌ {name}  🔴 Offline", context
                        )
                    await self.update_stats(user_id, context)

                elif action in ('shutdown', 'restart', 'sleep'):
                    cmd_map = {
                        'shutdown': self.executor.get_shutdown_command(device),
                        'restart': self.executor.get_restart_command(device),
                        'sleep': self.executor.get_sleep_command(device),
                    }
                    cmd = cmd_map.get(action, "")
                    if not cmd:
                        await self.update_action(
                            user_id, chat_id,
                            f"❌ {action.capitalize()} not supported for {device.os}", context
                        )
                        return

                    emoji = {'shutdown': '🛑', 'restart': '🔄', 'sleep': '💤'}[action]
                    await self.update_action(
                        user_id, chat_id,
                        f"{emoji} {name}\n⏳ Sending {action} command...", context
                    )
                    ok, out = await self.executor.ssh_command(device, cmd)
                    if ok or action in ('shutdown', 'restart'):
                        # SSH connection drop is expected for shutdown/restart  
                        await self.update_action(
                            user_id, chat_id,
                            f"{emoji} {name}\n✅ {action.capitalize()} command sent", context
                        )
                        # Update stats after a delay
                        await asyncio.sleep(5)
                        online = await self.executor.ping_device(device.ip)
                        self.state.update_device_status(name, online)
                        await self.update_stats(user_id, context)
                    else:
                        await self.update_action(
                            user_id, chat_id,
                            f"❌ {name}\n{action.capitalize()} failed: {out}", context
                        )

            except Exception as e:
                logger.error(f"Action {action} on {name} failed: {e}")
                await self.update_action(
                    user_id, chat_id,
                    f"❌ Error: {e}", context
                )

        task = asyncio.create_task(run_action())
        task.add_done_callback(
            lambda t: logger.error(f"Unhandled: {t.exception()}")
            if not t.cancelled() and t.exception() else None
        )

    # ─── Add Device Conversation ────────────────────────────────

    async def add_device_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Start the add-device conversation."""
        query = update.callback_query
        if query:
            await query.answer()
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id
        context.user_data.clear()
        await self.update_action(
            user_id, chat_id,
            "➕ Add Device\n━━━━━━━━━━━━━━━\nStep 1: Enter device name", context
        )
        return ADD_NAME

    async def add_name(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        name = update.message.text.strip()
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
        await self._delete_safe(chat_id, update.message.message_id, context)

        if not name or len(name) > 32:
            await self.update_action(
                user_id, chat_id,
                "❌ Name must be 1-32 characters.\n\nStep 1: Enter device name", context
            )
            return ADD_NAME
        if name in self.config.devices:
            await self.update_action(
                user_id, chat_id,
                f"❌ '{name}' already exists.\n\nStep 1: Enter device name", context
            )
            return ADD_NAME

        context.user_data['add_name'] = name
        await self.update_action(
            user_id, chat_id,
            f"✓ Name: {name}\n\nStep 2: Enter IP address", context
        )
        return ADD_IP

    async def add_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        ip = update.message.text.strip()
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
        await self._delete_safe(chat_id, update.message.message_id, context)

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            await self.update_action(
                user_id, chat_id,
                "❌ Invalid IP address.\n\nStep 2: Enter IP address", context
            )
            return ADD_IP

        context.user_data['add_ip'] = ip
        kb = [[InlineKeyboardButton(o, callback_data=f"os:{o.lower()}")]
              for o in ["Windows", "Linux", "macOS"]]
        await self.update_action(
            user_id, chat_id,
            f"✓ Name: {context.user_data['add_name']}\n"
            f"✓ IP: {ip}\n\nStep 3: Select OS",
            context, reply_markup=InlineKeyboardMarkup(kb)
        )
        return ADD_OS

    async def add_os(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        query = update.callback_query
        await query.answer()
        os_name = query.data.split(":", 1)[1]
        user_id = query.from_user.id
        chat_id = query.message.chat_id

        context.user_data['add_os'] = os_name
        kb = [
            [InlineKeyboardButton("✅ Yes", callback_data="wol:yes"),
             InlineKeyboardButton("❌ No", callback_data="wol:no")]
        ]
        await self.update_action(
            user_id, chat_id,
            f"✓ Name: {context.user_data['add_name']}\n"
            f"✓ IP: {context.user_data['add_ip']}\n"
            f"✓ OS: {os_name}\n\nStep 4: Does this device support Wake-on-LAN?",
            context, reply_markup=InlineKeyboardMarkup(kb)
        )
        return ADD_WOL

    async def add_wol(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        query = update.callback_query
        await query.answer()
        wol = query.data.split(":", 1)[1] == "yes"
        user_id = query.from_user.id
        chat_id = query.message.chat_id

        context.user_data['add_wol'] = wol

        if wol:
            await self.update_action(
                user_id, chat_id,
                f"✓ Name: {context.user_data['add_name']}\n"
                f"✓ IP: {context.user_data['add_ip']}\n"
                f"✓ OS: {context.user_data['add_os']}\n"
                f"✓ WoL: Yes\n\nStep 5: Enter MAC address (AA:BB:CC:DD:EE:FF)",
                context
            )
            return ADD_MAC
        else:
            context.user_data['add_mac'] = ''
            kb = [
                [InlineKeyboardButton("✅ Yes (SSH)", callback_data="ssh:yes"),
                 InlineKeyboardButton("❌ No (Ping only)", callback_data="ssh:no")]
            ]
            await self.update_action(
                user_id, chat_id,
                f"✓ Name: {context.user_data['add_name']}\n"
                f"✓ IP: {context.user_data['add_ip']}\n"
                f"✓ OS: {context.user_data['add_os']}\n"
                f"✓ WoL: No\n\nStep 5: Can this device be managed via SSH?",
                context, reply_markup=InlineKeyboardMarkup(kb)
            )
            return ADD_SSH

    async def add_mac(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        mac = update.message.text.strip().upper()
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
        await self._delete_safe(chat_id, update.message.message_id, context)

        mac_pattern = re.compile(r'^([0-9A-F]{2}[:-]){5}[0-9A-F]{2}$')
        if not mac_pattern.match(mac):
            await self.update_action(
                user_id, chat_id,
                "❌ Invalid MAC. Format: AA:BB:CC:DD:EE:FF\n\n"
                "Enter MAC address:", context
            )
            return ADD_MAC

        context.user_data['add_mac'] = mac
        kb = [
            [InlineKeyboardButton("✅ Yes (SSH)", callback_data="ssh:yes"),
             InlineKeyboardButton("❌ No (Ping only)", callback_data="ssh:no")]
        ]
        await self.update_action(
            user_id, chat_id,
            f"✓ Name: {context.user_data['add_name']}\n"
            f"✓ IP: {context.user_data['add_ip']}\n"
            f"✓ OS: {context.user_data['add_os']}\n"
            f"✓ WoL: Yes\n"
            f"✓ MAC: {mac}\n\nStep 6: Can this device be managed via SSH?",
            context, reply_markup=InlineKeyboardMarkup(kb)
        )
        return ADD_SSH

    async def add_ssh(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        query = update.callback_query
        await query.answer()
        ssh = query.data.split(":", 1)[1] == "yes"
        user_id = query.from_user.id
        chat_id = query.message.chat_id

        context.user_data['add_ssh'] = ssh

        if ssh:
            await self.update_action(
                user_id, chat_id,
                f"✓ Name: {context.user_data['add_name']}\n"
                f"✓ IP: {context.user_data['add_ip']}\n"
                f"✓ OS: {context.user_data['add_os']}\n"
                f"✓ WoL: {'Yes' if context.user_data['add_wol'] else 'No'}\n"
                f"✓ SSH: Yes\n\nFinal step: Enter SSH username",
                context
            )
            return ADD_USER
        else:
            # Ping-only device — create immediately
            return await self._finish_add_device(user_id, chat_id, '', context)

    async def add_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        ssh_user = update.message.text.strip()
        chat_id = update.effective_chat.id
        user_id = update.effective_user.id
        await self._delete_safe(chat_id, update.message.message_id, context)
        return await self._finish_add_device(user_id, chat_id, ssh_user, context)

    async def _finish_add_device(self, user_id, chat_id, ssh_user, context) -> int:
        """Create the device and update the UI."""
        device = Device(
            name=context.user_data['add_name'],
            ip=context.user_data['add_ip'],
            mac=context.user_data.get('add_mac', ''),
            os=context.user_data['add_os'],
            user=ssh_user,
            wol_capable=context.user_data.get('add_wol', False),
            ssh_capable=context.user_data.get('add_ssh', False)
        )
        self.config.add_device(device)

        caps = []
        if device.wol_capable:
            caps.append("WoL")
        if device.ssh_capable:
            caps.append("SSH")
        if not caps:
            caps.append("Ping only")

        await self.update_action(
            user_id, chat_id,
            f"✅ Device added!\n\n"
            f"Name: {device.name}\n"
            f"IP: {device.ip}\n"
            f"OS: {device.os}\n"
            f"Capabilities: {', '.join(caps)}", context
        )
        await self.update_panel(user_id, chat_id, context)
        return ConversationHandler.END

    async def add_cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Cancel the add-device flow."""
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id
        if update.message:
            await self._delete_safe(chat_id, update.message.message_id, context)
        await self.update_action(
            user_id, chat_id, self.build_action_text(), context
        )
        return ConversationHandler.END

    # ─── Monitor Callback ───────────────────────────────────────

    async def on_monitor_refresh(self):
        """Called by DeviceMonitor after each check cycle.
        
        Refreshes the stats message for all Telegram users.
        Uses the bot's application context directly.
        """
        if not self.app:
            return
        text = self.build_stats_text()
        for uid_str, stored in list(self.state.state["telegram"].items()):
            try:
                await self.app.bot.edit_message_text(
                    chat_id=stored["chat_id"],
                    message_id=stored["stats_msg_id"],
                    text=text
                )
            except Exception as e:
                if "Message is not modified" not in str(e):
                    logger.debug(f"Stats refresh for {uid_str}: {e}")

    # ─── Bot Setup & Run ────────────────────────────────────────

    def build_application(self):
        """Build and configure the Telegram application."""
        self.app = (
            ApplicationBuilder()
            .token(self.config.telegram_token)
            .connect_timeout(30)
            .read_timeout(30)
            .write_timeout(30)
            .build()
        )

        # Commands — /start is safe (no-op if panel exists), /panel force-recreates
        self.app.add_handler(CommandHandler("panel", self.panel_command))
        self.app.add_handler(CommandHandler("start", self.start_command))

        # Add device conversation
        self.app.add_handler(ConversationHandler(
            entry_points=[
                CallbackQueryHandler(self.add_device_start, pattern="^add_device$")
            ],
            states={
                ADD_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_name)],
                ADD_IP: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_ip)],
                ADD_OS: [CallbackQueryHandler(self.add_os, pattern="^os:")],
                ADD_WOL: [CallbackQueryHandler(self.add_wol, pattern="^wol:")],
                ADD_MAC: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_mac)],
                ADD_SSH: [CallbackQueryHandler(self.add_ssh, pattern="^ssh:")],
                ADD_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_user)],
            },
            fallbacks=[CommandHandler("cancel", self.add_cancel)],
            per_message=False,
        ))

        # General button callback (must be after ConversationHandler)
        self.app.add_handler(CallbackQueryHandler(self.button_callback))

        return self.app

    async def start_polling(self):
        """Start the bot polling with retry on network failures."""
        app = self.build_application()
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            try:
                await app.initialize()
                await app.start()
                await app.updater.start_polling(drop_pending_updates=True)
                logger.info("Telegram bot started polling")
                return
            except Exception as e:
                if attempt < max_retries:
                    wait = attempt * 5
                    logger.warning(
                        f"Telegram connect failed (attempt {attempt}/{max_retries}): {e}. "
                        f"Retrying in {wait}s..."
                    )
                    await asyncio.sleep(wait)
                else:
                    logger.error(f"Telegram connect failed after {max_retries} attempts: {e}")
                    raise

    async def stop_polling(self):
        """Stop the bot polling."""
        if self.app:
            await self.app.updater.stop()
            await self.app.stop()
            await self.app.shutdown()
            logger.info("Telegram bot stopped")

    def run(self):
        """Standalone run (for backward compatibility / simple usage)."""
        app = self.build_application()
        app.run_polling()
