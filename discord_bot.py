"""
Discord Bot — 3-message persistent UI for Wake-on-LAN device management.

Uses Discord embeds for rich formatting and persistent views
that survive bot restarts. All interactions edit existing messages
instead of sending new ones.

Supports DM-first architecture: authorized users get a personal DM panel,
and a global channel panel is maintained optionally if configured.
"""

import re
import asyncio
import logging
from datetime import datetime

import discord
from discord.ext import commands

from core.devices import Device, ConfigManager
from core.executor import CommandExecutor
from core.state import StateManager, format_time, utcnow

logger = logging.getLogger(__name__)


class DiscordBot:
    """Discord bot with DM-first 3-message persistent UI."""

    def __init__(self, config: ConfigManager, executor: CommandExecutor,
                 state: StateManager):
        self.config = config
        self.executor = executor
        self.state = state

        # Minimal intents: no message content needed for button/slash interactions
        intents = discord.Intents.default()
        self.bot = commands.Bot(
            command_prefix="!", intents=intents,
            help_command=None
        )
        self._setup_bot()

    def _setup_bot(self):
        """Register events and commands."""
        bot = self.bot
        parent = self

        @bot.event
        async def on_ready():
            logger.info(f"Discord bot logged in as {bot.user}")
            # Register persistent views
            bot.add_view(PanelView(parent))
            
            # Sync slash commands
            try:
                await bot.tree.sync()
                logger.info("Discord slash commands synced")
            except Exception as e:
                logger.error(f"Failed to sync slash commands: {e}")

            # Optionally initialize initial DM panels for authorized users on startup
            # (Better to wait for them to /panel, to avoid spamming)

        @bot.tree.command(name="panel", description="Open the device control panel")
        async def panel_cmd(interaction: discord.Interaction):
            await parent.panel_command(interaction)

    # ─── Embed Builders ─────────────────────────────────────────

    def build_stats_embed(self) -> discord.Embed:
        """Build the stats dashboard embed."""
        embed = discord.Embed(
            title="📊 System Dashboard",
            color=discord.Color.from_rgb(47, 49, 54)
        )

        # Bot status
        info = self.state.get_bot_info()
        node = info.get("node_name", "unknown")
        role = info.get("role", "unknown").capitalize()
        uptime = self.state.get_bot_uptime()
        now_str = format_time(utcnow())

        bot_status = (
            f"**Node:** {node} ({role})\n"
            f"**Uptime:** {uptime}\n"
            f"**Last check:** {now_str}"
        )
        embed.add_field(name="🤖 Bot Status", value=bot_status, inline=False)

        # Device statuses
        if self.config.devices:
            device_lines = []
            for name in self.config.devices:
                stats = self.state.get_device_stats(name)
                if stats and stats.get("online"):
                    icon = "🟢"
                    since = stats.get("online_since")
                    if since:
                        try:
                            dt = datetime.fromisoformat(since)
                            detail = f"Since {format_time(dt)}"
                        except (ValueError, TypeError):
                            detail = ""
                    else:
                        detail = "Just online"
                    device_lines.append(f"{icon} **{name}** — Online\n  └ {detail}")
                elif stats and stats.get("last_checked"):
                    try:
                        if stats.get("last_seen"):
                            dt = datetime.fromisoformat(stats["last_seen"])
                            detail = f"Last seen {format_time(dt)}"
                        else:
                            detail = "Never seen online"
                    except (ValueError, TypeError):
                        detail = ""
                    device_lines.append(f"🔴 **{name}** — Offline\n  └ {detail}")
                else:
                    device_lines.append(f"⚪ **{name}** — Unknown")

            embed.add_field(
                name="🖥 Devices",
                value="\n".join(device_lines) or "None",
                inline=False
            )

        # Failover
        failover_enabled = info.get("failover_enabled", True)
        if failover_enabled:
            primary_reachable = info.get("primary_reachable")
            role_lower = info.get("role", "primary")

            if role_lower == "primary":
                failover_text = f"🟢 **Primary ({node})** — Active\n🟢 **Backup** — Standby"
            elif primary_reachable:
                failover_text = f"🟢 **Primary** — Online\n🟡 **Backup ({node})** — Standby"
            else:
                failover_text = f"🔴 **Primary** — Down\n🟢 **Backup ({node})** — Active"

            embed.add_field(name="🛡 Failover", value=failover_text, inline=False)
            
        embed.set_footer(text="Auto-refreshes every 30s")
        return embed

    def build_action_embed(self, text: str = None) -> discord.Embed:
        """Build the action log embed."""
        embed = discord.Embed(
            title="📋 Action Log",
            description=text or "Ready\n\nPress a button on the panel below.",
            color=discord.Color.from_rgb(88, 101, 242)
        )
        return embed

    # ─── Message Management ─────────────────────────────────────

    async def _fetch_message(self, channel, msg_id: int):
        """Try to fetch a message by ID safely."""
        if not msg_id or not channel:
            return None
        try:
            return await channel.fetch_message(msg_id)
        except (discord.NotFound, discord.HTTPException, discord.Forbidden):
            return None

    async def _handle_panel_creation(self, channel, user_id=None):
        """Creates the 3 messages in the specified channel and updates state."""
        # Clean up old messages first
        if user_id:
            stored = self.state.get_discord_user(user_id)
        else:
            stored = self.state.get_discord()

        if stored:
            for key in ("stats_msg_id", "action_msg_id", "panel_msg_id"):
                if key in stored and stored[key]:
                    msg = await self._fetch_message(channel, stored[key])
                    if msg:
                        try:
                            await msg.delete()
                        except Exception:
                            pass

        # Send fresh messages
        stats_msg = await channel.send(embed=self.build_stats_embed())
        action_msg = await channel.send(embed=self.build_action_embed())
        panel_msg = await channel.send(
            content="🎛 **Device Control Panel**",
            view=PanelView(self, user_id=user_id)
        )

        # Save to state
        if user_id:
            self.state.set_discord_user(
                user_id, channel.id,
                stats_msg.id, action_msg.id, panel_msg.id
            )
        else:
            self.state.set_discord(
                channel.id,
                stats_msg.id, action_msg.id, panel_msg.id
            )

    async def panel_command(self, interaction: discord.Interaction):
        """Handle /panel command. Works in both DM and Guild channels."""
        user = interaction.user
        channel = interaction.channel

        if user.id not in self.config.discord_authorized_users:
            await interaction.response.send_message(
                "❌ You are not authorized to use this bot.", 
                ephemeral=True
            )
            return

        await interaction.response.defer(ephemeral=True)

        is_dm = isinstance(channel, discord.DMChannel) or channel is None
        
        if is_dm:
            # Explicitly interacting via DM
            if channel is None:
                channel = await user.create_dm()
            await self._handle_panel_creation(channel, user_id=user.id)
            await interaction.followup.send("✅ DM Panel created!", ephemeral=True)
            return

        # It's a guild channel. We ONLY handle it if it matches DISCORD_CHANNEL_ID
        if self.config.discord_channel_id and channel.id == self.config.discord_channel_id:
            await self._handle_panel_creation(channel, user_id=None)
            await interaction.followup.send("✅ Channel panel created!", ephemeral=True)
        else:
            # Fallback path: User called /panel in a random channel
            # Create a DM panel for them instead
            dm_channel = await user.create_dm()
            await self._handle_panel_creation(dm_channel, user_id=user.id)
            await interaction.followup.send("✅ Panel created in your DMs!", ephemeral=True)

    async def _update_embed_safely(self, channel_id: int, msg_id: int, 
                                   embed: discord.Embed, content: str = None, 
                                   view: discord.ui.View = None):
        """Helper to safely edit a message over the API."""
        if not channel_id or not msg_id:
            return False
            
        try:
            channel = self.bot.get_channel(channel_id)
            if not channel:
                channel = await self.bot.fetch_channel(channel_id)
            
            msg = await self._fetch_message(channel, msg_id)
            if msg:
                kwargs = {"embed": embed}
                if content is not None:
                    kwargs["content"] = content
                if view is not None:
                    kwargs["view"] = view
                await msg.edit(**kwargs)
                return True
        except Exception as e:
            logger.debug(f"Failed to update Discord message {msg_id}: {e}")
        return False

    async def update_stats(self):
        """Refresh the stats embed across all active panels (channel + DMs)."""
        embed = self.build_stats_embed()
        
        # 1. Update Global Channel (if exists)
        channel_state = self.state.get_discord()
        if channel_state and channel_state.get("stats_msg_id"):
            await self._update_embed_safely(
                channel_state.get("channel_id"), 
                channel_state.get("stats_msg_id"), 
                embed
            )
            
        # 2. Update DMs for all active users
        for user_id_str, dm_state in self.state.state.get("discord_users", {}).items():
            if dm_state.get("stats_msg_id"):
                await self._update_embed_safely(
                    dm_state.get("dm_channel_id"), 
                    dm_state.get("stats_msg_id"), 
                    embed
                )

    async def update_action(self, text: str, user_id: int = None):
        """
        Update the action log embed.
        If user_id is provided, only updates their DM. Let's make it targeted.
        If user_id is None, updates the global channel.
        """
        embed = self.build_action_embed(text)
        
        if user_id:
            dm_state = self.state.get_discord_user(user_id)
            if dm_state and dm_state.get("action_msg_id"):
                await self._update_embed_safely(
                    dm_state.get("dm_channel_id"), 
                    dm_state.get("action_msg_id"), 
                    embed
                )
        else:
            channel_state = self.state.get_discord()
            if channel_state and channel_state.get("action_msg_id"):
                await self._update_embed_safely(
                    channel_state.get("channel_id"), 
                    channel_state.get("action_msg_id"), 
                    embed
                )

    async def on_monitor_refresh(self):
        """Called by DeviceMonitor."""
        await self.update_stats()

    async def start(self):
        """Start the Discord bot."""
        await self.bot.start(self.config.discord_token)

    async def stop(self):
        """Stop the Discord bot."""
        await self.bot.close()


class PanelView(discord.ui.View):
    """Persistent panel view with device control buttons."""

    def __init__(self, bot: DiscordBot, user_id: int = None):
        super().__init__(timeout=None)
        self.dbot = bot
        self.user_id = user_id  # Keep track of context (DM vs Channel)
        self.clear_items()
        self._build_buttons()

    def _build_buttons(self):
        """Dynamically build buttons based on configured devices."""
        # Management row
        self.add_item(PanelButton(
            self.dbot, label="➕ Add", custom_id=f"dc_add_device",
            style=discord.ButtonStyle.secondary, row=0
        ))
        self.add_item(PanelButton(
            self.dbot, label="🗑️ Remove", custom_id=f"dc_remove_device",
            style=discord.ButtonStyle.secondary, row=0
        ))
        self.add_item(PanelButton(
            self.dbot, label="🔄 Refresh", custom_id=f"dc_refresh",
            style=discord.ButtonStyle.secondary, row=0
        ))

        # Device buttons (max 5 rows total in Discord, limit to 4 devices to fit row 0)
        row = 1
        for name, device in list(self.dbot.config.devices.items())[:4]:
            # Device name is click-to-ping for status (like Telegram)
            self.add_item(PanelButton(
                self.dbot, label=f"  {name}  ", custom_id=f"dc_status:{name}",
                style=discord.ButtonStyle.primary, row=row
            ))
            if device.wol_capable:
                self.add_item(PanelButton(
                    self.dbot, label="🟢", custom_id=f"dc_wake:{name}",
                    style=discord.ButtonStyle.success, row=row
                ))
            if device.ssh_capable:
                self.add_item(PanelButton(
                    self.dbot, label="🛑", custom_id=f"dc_shutdown:{name}",
                    style=discord.ButtonStyle.danger, row=row
                ))
                self.add_item(PanelButton(
                    self.dbot, label="🔄", custom_id=f"dc_restart:{name}",
                    style=discord.ButtonStyle.danger, row=row
                ))
                self.add_item(PanelButton(
                    self.dbot, label="💤", custom_id=f"dc_sleep:{name}",
                    style=discord.ButtonStyle.secondary, row=row
                ))
            row += 1

class PanelButton(discord.ui.Button):
    """A button on the device control panel."""

    def __init__(self, dbot: DiscordBot, **kwargs):
        super().__init__(**kwargs)
        self.dbot = dbot

    async def callback(self, interaction: discord.Interaction):
        user = interaction.user
        if user.id not in self.dbot.config.discord_authorized_users:
            await interaction.response.send_message(
                "❌ You are not authorized.", ephemeral=True
            )
            return

        # Determine context (was this clicked in a DM or in the Global Channel?)
        is_dm = isinstance(interaction.channel, discord.DMChannel) or interaction.channel is None
        target_uid = user.id if is_dm else None

        await interaction.response.defer()
        action_id = self.custom_id

        if action_id == "dc_refresh":
            await self.dbot.update_action("🔄 Refreshing...", user_id=target_uid)
            # Parallel check for speed
            async def _check(n, d):
                return n, await self.dbot.executor.check_device_status(d, timeout=5)
            
            results = await asyncio.gather(*[_check(name, self.dbot.config.devices[name]) for name in self.dbot.config.devices])
            for name, online in results:
                self.dbot.state.update_device_status(name, online, save=False)
            self.dbot.state.save()
            
            await self.dbot.update_stats()
            await self.dbot.update_action("✅ Stats refreshed!", user_id=target_uid)
            return

        if action_id == "dc_add_device":
            await self.dbot.update_action(
                "➕ To add devices, please use the Telegram bot or edit devices.json directly.", 
                user_id=target_uid
            )
            return

        if action_id == "dc_remove_device":
            await self.dbot.update_action(
                "🗑️ To remove devices, please use the Telegram bot or edit devices.json directly.", 
                user_id=target_uid
            )
            return

        # Device actions: dc_wake:name, dc_shutdown:name, dc_status:name, etc.
        if ":" not in action_id:
            return

        _, rest = action_id.split("_", 1)
        action, name = rest.split(":", 1)
        device = self.dbot.config.devices.get(name)
        if not device:
            await self.dbot.update_action(f"❌ Device '{name}' not found", user_id=target_uid)
            return

        if action == "wake":
            await self.dbot.update_action(f"🟢 {name}\n📡 Sending WOL packet...", user_id=target_uid)
            await self.dbot.executor.wake_device(device.mac)
            await self.dbot.update_action(f"🟢 {name}\n📡 WOL sent, waiting for response...", user_id=target_uid)
            await asyncio.sleep(2)
            for i in range(12):
                if await self.dbot.executor.ping_device(device.ip):
                    self.dbot.state.update_device_status(name, True)
                    await self.dbot.update_action(f"✅ {name}\n🟢 ONLINE", user_id=target_uid)
                    await self.dbot.update_stats()
                    return
                await self.dbot.update_action(f"🟢 {name}\n🔍 Pinging... ({i+1}/12)", user_id=target_uid)
                await asyncio.sleep(5)
            await self.dbot.update_action(f"⚠️ {name}\n❌ Timeout — device did not respond", user_id=target_uid)

        elif action == "status":
            await self.dbot.update_action(f"🔍 {name}\n⏳ Checking...", user_id=target_uid)
            online = await self.dbot.executor.check_device_status(device, timeout=5)
            self.dbot.state.update_device_status(name, online)
            
            if online:
                await self.dbot.update_action(f"✅ {name}  🟢 Online", user_id=target_uid)
            else:
                await self.dbot.update_action(f"❌ {name}  🔴 Offline", user_id=target_uid)
            await self.dbot.update_stats()

        elif action in ("shutdown", "restart", "sleep"):
            cmd_map = {
                'shutdown': self.dbot.executor.get_shutdown_command(device),
                'restart': self.dbot.executor.get_restart_command(device),
                'sleep': self.dbot.executor.get_sleep_command(device),
            }
            cmd = cmd_map.get(action, "")
            emoji = {'shutdown': '🛑', 'restart': '🔄', 'sleep': '💤'}[action]
            
            await self.dbot.update_action(f"{emoji} {name}\n⏳ Sending {action}...", user_id=target_uid)
            ok, out = await self.dbot.executor.ssh_command(device, cmd)
            if ok or action in ('shutdown', 'restart'):
                await self.dbot.update_action(f"{emoji} {name}\n✅ {action.capitalize()} command sent", user_id=target_uid)
                await asyncio.sleep(5)
                online = await self.dbot.executor.ping_device(device.ip)
                self.dbot.state.update_device_status(name, online)
                await self.dbot.update_stats()
            else:
                await self.dbot.update_action(f"❌ {name}\n{action.capitalize()} failed: {out}", user_id=target_uid)
