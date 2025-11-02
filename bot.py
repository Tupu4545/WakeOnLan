import os
import json
import asyncio
import re
import sys
from typing import Dict, List, Optional, Tuple, Callable
from pathlib import Path
import ipaddress
from dataclasses import dataclass
from shutil import copy2

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, ContextTypes, 
    CallbackQueryHandler, ConversationHandler, MessageHandler, filters
)
from wakeonlan import send_magic_packet
from dotenv import load_dotenv

ADD_NAME, ADD_IP, ADD_MAC, ADD_OS, ADD_USER, ADD_PORT, ADD_SSH_KEY = range(7)

@dataclass
class Device:
    name: str
    ip: str
    mac: str
    os: str
    user: str
    ssh_key: Optional[str] = None
    port: int = 22
    
    def __post_init__(self):
        self._validate_ip()
        self._validate_mac()
        self._validate_os()
    
    def _validate_ip(self):
        try:
            ipaddress.ip_address(self.ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {self.ip}")
    
    def _validate_mac(self):
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        if not re.match(mac_pattern, self.mac):
            raise ValueError(f"Invalid MAC address: {self.mac}")
    
    def _validate_os(self):
        valid_os = ['windows', 'linux', 'macos']
        if self.os.lower() not in valid_os:
            raise ValueError(f"Invalid OS type: {self.os}. Must be one of {valid_os}")
    
    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'os': self.os,
            'user': self.user,
            'ssh_key': self.ssh_key,
            'port': self.port
        }

class ConfigManager:
    def __init__(self, devices_file: str = "devices.json"):
        self.devices_file = Path(devices_file)
        self.devices: Dict[str, Device] = {}
        self.authorized_user_ids: List[int] = []
        self.token: str = ""
        
    def load_config(self):
        self._load_env()
        self._load_devices()
    
    def _load_env(self):
        load_dotenv()
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        if not self.token:
            raise ValueError("TELEGRAM_BOT_TOKEN not set in .env file")
        
        users_env = os.getenv("AUTHORIZED_USER_IDS", "")
        if users_env:
            try:
                self.authorized_user_ids = [int(uid.strip()) for uid in users_env.split(",")]
            except ValueError:
                raise ValueError("AUTHORIZED_USER_IDS must contain valid integer user IDs separated by commas")
        else:
            raise ValueError("AUTHORIZED_USER_IDS not set in .env file")
        
    def _load_devices(self):
        if not self.devices_file.exists():
            with open(self.devices_file, "w") as f:
                json.dump({}, f, indent=2)
            return
        
        try:
            with open(self.devices_file, "r") as f:
                devices_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {self.devices_file}: {str(e)}")
        
        for name, config in devices_data.items():
            try:
                device = Device(
                    name=name,
                    ip=config['ip'],
                    mac=config['mac'],
                    os=config['os'],
                    user=config['user'],
                    ssh_key=config.get('ssh_key'),
                    port=config.get('port', 22)
                )
                self.devices[name] = device
            except (KeyError, ValueError) as e:
                print(f"Invalid device configuration for {name}: {e}")
                continue
    
    def save_devices(self, backup: bool = True):
        if backup and self.devices_file.exists():
            backup_file = self.devices_file.with_suffix('.json.backup')
            copy2(self.devices_file, backup_file)
        
        devices_dict = {name: device.to_dict() for name, device in self.devices.items()}
        
        with open(self.devices_file, 'w') as f:
            json.dump(devices_dict, f, indent=2)
    
    def add_device(self, device: Device):
        self.devices[device.name] = device
        self.save_devices()
    
    def remove_device(self, device_name: str) -> bool:
        if device_name in self.devices:
            del self.devices[device_name]
            self.save_devices()
            return True
        return False

class CommandExecutor:
    @staticmethod
    async def ping_device(ip: str, timeout: int = 2) -> bool:
        try:
            process = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(timeout), ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            return_code = await process.wait()
            return return_code == 0
        except Exception:
            return False
    
    @staticmethod
    async def ssh_command(device: Device, command: str, timeout: int = 10) -> Tuple[bool, str]:
        ssh_cmd = ["ssh", "-o", f"ConnectTimeout={timeout}", "-o", "StrictHostKeyChecking=no"]
        
        if device.ssh_key:
            ssh_cmd.extend(["-i", device.ssh_key])
        
        if device.port != 22:
            ssh_cmd.extend(["-p", str(device.port)])
        
        ssh_cmd.extend([f"{device.user}@{device.ip}", command])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            success = process.returncode == 0
            output = stdout.decode() if stdout else stderr.decode()
            return success, output.strip()
        except Exception as e:
            return False, str(e)

class DeviceBot:
    def __init__(self):
        self.config = ConfigManager()
        self.executor = CommandExecutor()
        self.user_status_messages: Dict[int, int] = {}
        self.user_menu_messages: Dict[int, int] = {}
        
    def is_authorized(self, user_id: int) -> bool:
        return user_id in self.config.authorized_user_ids
    
    @staticmethod
    def format_device_key(key: str) -> str:
        slug = re.sub(r'[^a-zA-Z0-9_]', '_', key.lower())
        return re.sub(r'_+', '_', slug).strip('_')
    
    def generate_help_message(self) -> str:
        lines = ["Available Commands:\n"]
        lines.append("Device Management:")
        lines.append("• /menu - Interactive device control panel")
        lines.append("• /list - List all devices")
        lines.append("• /add_device - Add a new device")
        lines.append("• /remove_device - Remove a device\n")
        
        if self.config.devices:
            lines.append("Device Commands:")
            for device_name, device in self.config.devices.items():
                slug = self.format_device_key(device_name)
                lines.append(f"\n{device_name} ({device.os}):")
                lines.append(f"• /wake_{slug} - Wake device")
                lines.append(f"• /shutdown_{slug} - Shutdown device")
                lines.append(f"• /restart_{slug} - Restart device")
                lines.append(f"• /status_{slug} - Check device status")
                
                if device.os.lower() == 'windows':
                    lines.append(f"• /sleep_{slug} - Put device to sleep")
        
        return "\n".join(lines)
    
    async def send_unauthorized(self, update: Update) -> None:
        message = f"Access Denied\nYou are not authorized to use this bot.\n\nYour User ID: {update.effective_user.id}"
        if hasattr(update, 'message') and update.message:
            await update.message.reply_text(message)
        elif update.callback_query:
            await update.callback_query.message.reply_text(message)
    
    async def ensure_status_message(self, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> int:
        if user_id not in self.user_status_messages:
            status_msg = await context.bot.send_message(chat_id=chat_id, text="Ready")
            self.user_status_messages[user_id] = status_msg.message_id
        return self.user_status_messages[user_id]
    
    async def update_status_message(self, user_id: int, chat_id: int, text: str, context: ContextTypes.DEFAULT_TYPE, reply_markup=None):
        message_id = await self.ensure_status_message(user_id, chat_id, context)
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id, 
                message_id=message_id, 
                text=text,
                reply_markup=reply_markup
            )
        except Exception:
            pass
    
    async def delete_message_safe(self, chat_id: int, message_id: int, context: ContextTypes.DEFAULT_TYPE):
        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
        except Exception:
            pass
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return await self.send_unauthorized(update)
        
        welcome_msg = await update.message.reply_text(
            f"Device Management Bot\n\nWelcome, {update.effective_user.first_name}!\n\nUse /menu for controls or /help for command list."
        )
        
        await self.menu_command(update, context)
        
        await asyncio.sleep(3)
        await self.delete_message_safe(update.message.chat_id, welcome_msg.message_id, context)
        await self.delete_message_safe(update.message.chat_id, update.message.message_id, context)
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return await self.send_unauthorized(update)
        
        help_text = self.generate_help_message()
        await self.update_status_message(user_id, update.message.chat_id, help_text, context)
        await self.delete_message_safe(update.message.chat_id, update.message.message_id, context)
    
    async def list_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return await self.send_unauthorized(update)
        
        if not self.config.devices:
            await self.update_status_message(user_id, update.message.chat_id, "No devices configured\n\nUse the Add Device button to add your first device!", context)
            await self.delete_message_safe(update.message.chat_id, update.message.message_id, context)
            return
        
        message = "Configured Devices:\n\n"
        for name, device in self.config.devices.items():
            message += f"{name}\n"
            message += f"• IP: {device.ip}\n"
            message += f"• MAC: {device.mac}\n"
            message += f"• OS: {device.os}\n"
            message += f"• User: {device.user}\n"
            message += f"• Port: {device.port}\n"
            if device.ssh_key:
                message += f"• SSH Key: {device.ssh_key}\n"
            message += "\n"
        
        await self.update_status_message(user_id, update.message.chat_id, message, context)
        await self.delete_message_safe(update.message.chat_id, update.message.message_id, context)
    
    def create_menu_keyboard(self):
        keyboard = []
        
        keyboard.append([
            InlineKeyboardButton("➕", callback_data="add_device"),
            InlineKeyboardButton("➖", callback_data="remove_device_menu"),
            InlineKeyboardButton("📋", callback_data="list_devices")
        ])
        
        if self.config.devices:
            keyboard.append([InlineKeyboardButton("━━━━━━━━━━━━", callback_data="none")])
        
        for device_name, device in self.config.devices.items():
            row = [
                InlineKeyboardButton("🟢", callback_data=f"wake:{device_name}"),
                InlineKeyboardButton("🛑", callback_data=f"shutdown:{device_name}"),
                InlineKeyboardButton("🔄", callback_data=f"restart:{device_name}"),
                InlineKeyboardButton("📊", callback_data=f"status:{device_name}")
            ]
            
            if device.os.lower() == 'windows':
                row.append(InlineKeyboardButton("💤", callback_data=f"sleep:{device_name}"))
            
            keyboard.append([InlineKeyboardButton(f"{device_name}", callback_data="none")])
            keyboard.append(row)
        
        return InlineKeyboardMarkup(keyboard)
    
    async def menu_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            return await self.send_unauthorized(update)
        
        if not self.config.devices:
            message = "Device Control Panel\n\nNo devices configured yet.\nUse the buttons below to add devices."
        else:
            message = "Device Control Panel\nSelect an action:"
        
        reply_markup = self.create_menu_keyboard()
        
        if user_id in self.user_menu_messages:
            try:
                await context.bot.edit_message_text(
                    chat_id=update.message.chat_id,
                    message_id=self.user_menu_messages[user_id],
                    text=message,
                    reply_markup=reply_markup
                )
            except Exception:
                menu_msg = await update.message.reply_text(message, reply_markup=reply_markup)
                self.user_menu_messages[user_id] = menu_msg.message_id
        else:
            menu_msg = await update.message.reply_text(message, reply_markup=reply_markup)
            self.user_menu_messages[user_id] = menu_msg.message_id
        
        await self.ensure_status_message(user_id, update.message.chat_id, context)
        
        if update.message:
            await self.delete_message_safe(update.message.chat_id, update.message.message_id, context)
    
    async def refresh_menu(self, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        if not self.config.devices:
            message = "Device Control Panel\n\nNo devices configured yet.\nUse the buttons below to add devices."
        else:
            message = "Device Control Panel\nSelect an action:"
        
        reply_markup = self.create_menu_keyboard()
        
        try:
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=self.user_menu_messages[user_id],
                text=message,
                reply_markup=reply_markup
            )
        except Exception:
            pass
    
    async def add_device_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        query = update.callback_query
        
        if query:
            await query.answer()
            user_id = query.from_user.id
            chat_id = query.message.chat_id
            if not self.is_authorized(user_id):
                await self.update_status_message(user_id, chat_id, "Access Denied", context)
                return ConversationHandler.END
            
            context.user_data['conversation_messages'] = []
            
            await self.update_status_message(
                user_id, 
                chat_id,
                "Add New Device\n\nStep 1/7: Enter device name\n(e.g., My-Laptop, Office-PC)\n\nSend /cancel to abort.",
                context
            )
        else:
            user_id = update.effective_user.id
            chat_id = update.message.chat_id
            if not self.is_authorized(user_id):
                return await self.send_unauthorized(update)
            
            context.user_data['conversation_messages'] = [update.message.message_id]
            
            await self.update_status_message(
                user_id,
                chat_id,
                "Add New Device\n\nStep 1/7: Enter device name\n(e.g., My-Laptop, Office-PC)\n\nSend /cancel to abort.",
                context
            )
        
        return ADD_NAME
    
    async def add_device_name(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        device_name = update.message.text.strip()
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        if not device_name or len(device_name) < 2:
            await self.update_status_message(user_id, chat_id, "Device name must be at least 2 characters long. Try again:", context)
            return ADD_NAME
        
        if device_name in self.config.devices:
            await self.update_status_message(user_id, chat_id, f"Device '{device_name}' already exists. Choose a different name:", context)
            return ADD_NAME
        
        context.user_data['new_device_name'] = device_name
        
        await self.update_status_message(
            user_id, chat_id,
            f"Device name: {device_name}\n\nStep 2/7: Enter IP address\n(e.g., 192.168.1.100)",
            context
        )
        return ADD_IP
    
    async def add_device_ip(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        ip_address = update.message.text.strip()
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            await self.update_status_message(user_id, chat_id, "Invalid IP address. Try again:", context)
            return ADD_IP
        
        context.user_data['new_device_ip'] = ip_address
        
        await self.update_status_message(
            user_id, chat_id,
            f"IP: {ip_address}\n\nStep 3/7: Enter MAC address\n(e.g., AA:BB:CC:DD:EE:FF)",
            context
        )
        return ADD_MAC
    
    async def add_device_mac(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        mac_address = update.message.text.strip().upper()
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        mac_pattern = r'^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$'
        if not re.match(mac_pattern, mac_address):
            await self.update_status_message(user_id, chat_id, "Invalid MAC address. Try again:", context)
            return ADD_MAC
        
        context.user_data['new_device_mac'] = mac_address
        
        keyboard = [
            [InlineKeyboardButton("Windows", callback_data="os:windows")],
            [InlineKeyboardButton("Linux", callback_data="os:linux")],
            [InlineKeyboardButton("macOS", callback_data="os:macos")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await self.update_status_message(
            user_id, chat_id,
            f"MAC: {mac_address}\n\nStep 4/7: Select OS:",
            context,
            reply_markup=reply_markup
        )
        return ADD_OS
    
    async def add_device_os(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        query = update.callback_query
        await query.answer()
        
        os_type = query.data.split(":")[1]
        context.user_data['new_device_os'] = os_type
        
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        await self.update_status_message(
            user_id, chat_id,
            f"OS: {os_type}\n\nStep 5/7: Enter SSH username\n(e.g., admin, root)",
            context
        )
        return ADD_USER
    
    async def add_device_user(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        username = update.message.text.strip()
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        if not username:
            await self.update_status_message(user_id, chat_id, "Username cannot be empty. Try again:", context)
            return ADD_USER
        
        context.user_data['new_device_user'] = username
        
        await self.update_status_message(
            user_id, chat_id,
            f"User: {username}\n\nStep 6/7: Enter SSH port\n(Send /skip for default 22)",
            context
        )
        return ADD_PORT
    
    async def add_device_port(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        port_text = update.message.text.strip()
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        try:
            port = int(port_text)
            if port < 1 or port > 65535:
                raise ValueError
        except ValueError:
            await self.update_status_message(user_id, chat_id, "Invalid port. Try again or /skip:", context)
            return ADD_PORT
        
        context.user_data['new_device_port'] = port
        
        await self.update_status_message(
            user_id, chat_id,
            f"Port: {port}\n\nStep 7/7: Enter SSH key path\n(Send /skip if not needed)",
            context
        )
        return ADD_SSH_KEY
    
    async def add_device_skip_port(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        context.user_data['new_device_port'] = 22
        
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        await self.update_status_message(
            user_id, chat_id,
            "Port: 22 (default)\n\nStep 7/7: Enter SSH key path\n(Send /skip if not needed)",
            context
        )
        return ADD_SSH_KEY
    
    async def add_device_ssh_key(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        ssh_key = update.message.text.strip()
        context.user_data['new_device_ssh_key'] = ssh_key
        return await self.add_device_confirm(update, context)
    
    async def add_device_skip_ssh_key(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        context.user_data['conversation_messages'].append(update.message.message_id)
        context.user_data['new_device_ssh_key'] = None
        return await self.add_device_confirm(update, context)
    
    async def add_device_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        user_id = update.effective_user.id
        chat_id = update.message.chat_id if update.message else update.callback_query.message.chat_id
        
        try:
            device = Device(
                name=context.user_data['new_device_name'],
                ip=context.user_data['new_device_ip'],
                mac=context.user_data['new_device_mac'],
                os=context.user_data['new_device_os'],
                user=context.user_data['new_device_user'],
                ssh_key=context.user_data.get('new_device_ssh_key'),
                port=context.user_data.get('new_device_port', 22)
            )
            
            self.config.add_device(device)
            
            message = f"Device Added!\n\n{device.name}\nIP: {device.ip}\nMAC: {device.mac}\nOS: {device.os}"
            
            await self.update_status_message(user_id, chat_id, message, context)
            
            for msg_id in context.user_data.get('conversation_messages', []):
                await self.delete_message_safe(chat_id, msg_id, context)
            
            context.user_data.clear()
            
            if user_id in self.user_menu_messages:
                await self.refresh_menu(user_id, chat_id, context)
            
            return ConversationHandler.END
            
        except Exception as e:
            await self.update_status_message(user_id, chat_id, f"Error: {str(e)}", context)
            
            for msg_id in context.user_data.get('conversation_messages', []):
                await self.delete_message_safe(chat_id, msg_id, context)
            
            context.user_data.clear()
            return ConversationHandler.END
    
    async def add_device_cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        user_id = update.effective_user.id
        chat_id = update.message.chat_id
        
        context.user_data['conversation_messages'].append(update.message.message_id)
        
        await self.update_status_message(user_id, chat_id, "Cancelled.", context)
        
        for msg_id in context.user_data.get('conversation_messages', []):
            await self.delete_message_safe(chat_id, msg_id, context)
        
        context.user_data.clear()
        return ConversationHandler.END
    
    async def remove_device_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        if not self.is_authorized(user_id):
            await self.update_status_message(user_id, chat_id, "Access Denied", context)
            return
        
        if not self.config.devices:
            await self.update_status_message(user_id, chat_id, "No devices to remove", context)
            return
        
        keyboard = []
        for device_name in self.config.devices.keys():
            keyboard.append([InlineKeyboardButton(f"🗑️ {device_name}", callback_data=f"remove:{device_name}")])
        
        keyboard.append([InlineKeyboardButton("❌ Cancel", callback_data="cancel_remove")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await self.update_status_message(user_id, chat_id, "Select device to remove:", context, reply_markup=reply_markup)
    
    async def remove_device_confirm(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        device_name = query.data.split(":")[1]
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        keyboard = [
            [
                InlineKeyboardButton("✅ Yes", callback_data=f"remove_confirm:{device_name}"),
                InlineKeyboardButton("❌ No", callback_data="cancel_remove")
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await self.update_status_message(
            user_id, chat_id,
            f"Remove {device_name}?\n\nThis cannot be undone.",
            context,
            reply_markup=reply_markup
        )
    
    async def remove_device_execute(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        device_name = query.data.split(":")[1]
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        if self.config.remove_device(device_name):
            await self.update_status_message(user_id, chat_id, f"{device_name} removed!", context)
            
            if user_id in self.user_menu_messages:
                await self.refresh_menu(user_id, chat_id, context)
        else:
            await self.update_status_message(user_id, chat_id, f"Failed to remove {device_name}", context)
    
    async def cancel_remove(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        await self.update_status_message(user_id, chat_id, "Cancelled.", context)
    
    async def list_devices_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        chat_id = query.message.chat_id
        
        if not self.config.devices:
            await self.update_status_message(user_id, chat_id, "No devices configured", context)
            return
        
        message = "Configured Devices:\n\n"
        for name, device in self.config.devices.items():
            message += f"{name}\n"
            message += f"• IP: {device.ip}\n"
            message += f"• MAC: {device.mac}\n"
            message += f"• OS: {device.os}\n"
            message += f"• User: {device.user}\n"
            message += f"• Port: {device.port}\n"
            if device.ssh_key:
                message += f"• SSH Key: {device.ssh_key}\n"
            message += "\n"
        
        await self.update_status_message(user_id, chat_id, message, context)
    
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        if not self.is_authorized(user_id):
            return
        
        if query.data == "none":
            return
        
        if query.data == "remove_device_menu":
            return await self.remove_device_menu(update, context)
        
        if query.data.startswith("remove:") and not query.data.startswith("remove_confirm:"):
            return await self.remove_device_confirm(update, context)
        
        if query.data.startswith("remove_confirm:"):
            return await self.remove_device_execute(update, context)
        
        if query.data == "cancel_remove":
            return await self.cancel_remove(update, context)
        
        if query.data == "list_devices":
            return await self.list_devices_callback(update, context)
        
        try:
            action, device_name = query.data.split(":", 1)
        except ValueError:
            return
        
        await self._execute_device_action(action, device_name, user_id, query.message.chat_id, context)
    
    async def _execute_device_action(self, action: str, device_name: str, user_id: int, 
                                   chat_id: int, context: ContextTypes.DEFAULT_TYPE) -> None:
        device = self.config.devices.get(device_name)
        if not device:
            await self.update_status_message(user_id, chat_id, f"Device '{device_name}' not found", context)
            return
        
        try:
            if action == 'wake':
                await self._wake_device(device, user_id, chat_id, context)
            elif action == 'shutdown':
                await self._shutdown_device(device, user_id, chat_id, context)
            elif action == 'restart':
                await self._restart_device(device, user_id, chat_id, context)
            elif action == 'sleep':
                await self._sleep_device(device, user_id, chat_id, context)
            elif action == 'status':
                await self._status_device(device, user_id, chat_id, context)
            else:
                await self.update_status_message(user_id, chat_id, f"Unknown action: {action}", context)
        
        except Exception as e:
            error_msg = f"Action Failed\nDevice: {device.name}\nAction: {action}\nError: {str(e)}"
            await self.update_status_message(user_id, chat_id, error_msg, context)
    
    async def _wake_device(self, device: Device, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        send_magic_packet(device.mac)
        await self.update_status_message(user_id, chat_id, f"Wake-on-LAN sent to {device.name}", context)
        
        await asyncio.sleep(2)
        await self.update_status_message(user_id, chat_id, f"Wake-on-LAN sent to {device.name}\nWaiting for ping...", context)
        
        max_attempts = 12
        for attempt in range(max_attempts):
            is_up = await self.executor.ping_device(device.ip)
            if is_up:
                await self.update_status_message(user_id, chat_id, f"{device.name} is now UP", context)
                return
            await asyncio.sleep(5)
        
        await self.update_status_message(user_id, chat_id, f"{device.name} did not start within 60 seconds❌\nCheck manually", context)
    
    async def _shutdown_device(self, device: Device, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        shutdown_cmd = "shutdown /s /t 0" if device.os.lower() == 'windows' else "sudo -n /sbin/shutdown -h now"
        
        await self.update_status_message(user_id, chat_id, f"Sending shutdown command to {device.name}...", context)
        
        success, output = await self.executor.ssh_command(device, shutdown_cmd)
        
        if not success:
            await self.update_status_message(user_id, chat_id, f"Shutdown failed for {device.name}\nError: {output}", context)
            return
        
        await self.update_status_message(user_id, chat_id, f"Shutdown command sent to {device.name}🟡\nWaiting for device to go down...", context)
        
        max_attempts = 12
        for attempt in range(max_attempts):
            await asyncio.sleep(5)
            is_up = await self.executor.ping_device(device.ip)
            if not is_up:
                await self.update_status_message(user_id, chat_id, f"{device.name} is now DOWN🛑", context)
                return
        
        await self.update_status_message(user_id, chat_id, f"{device.name} is still UP after 60 seconds🟡\nCheck manually", context)
    
    async def _restart_device(self, device: Device, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        restart_cmd = "shutdown /r /t 0" if device.os.lower() == 'windows' else "sudo -n reboot now"
        
        await self.update_status_message(user_id, chat_id, f"Sending restart command to {device.name}...", context)
        
        success, output = await self.executor.ssh_command(device, restart_cmd)
        
        if not success:
            await self.update_status_message(user_id, chat_id, f"Restart failed for {device.name}\nError: {output}", context)
            return
        
        await self.update_status_message(user_id, chat_id, f"Restart command sent to {device.name}\nWaiting for device to go down...", context)
        
        await asyncio.sleep(10)
        
        down_detected = False
        for attempt in range(6):
            await asyncio.sleep(5)
            is_up = await self.executor.ping_device(device.ip)
            if not is_up:
                down_detected = True
                break
        
        if not down_detected:
            await self.update_status_message(user_id, chat_id, f"{device.name} did not go down❌\nRestart may have failed", context)
            return
        
        await self.update_status_message(user_id, chat_id, f"{device.name} is down 🟡 \nWaiting for device to come back up...", context)
        
        max_attempts = 24
        for attempt in range(max_attempts):
            await asyncio.sleep(5)
            is_up = await self.executor.ping_device(device.ip)
            if is_up:
                await self.update_status_message(user_id, chat_id, f"{device.name} is UP ✅ after restart", context)
                return
        
        await self.update_status_message(user_id, chat_id, f"{device.name} did not come back up within 120 seconds❌\nCheck manually", context)
    
    async def _sleep_device(self, device: Device, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        if device.os.lower() != 'windows':
            await self.update_status_message(user_id, chat_id, f"Sleep command only supported for Windows devices\n{device.name} is running {device.os}", context)
            return
        
        sleep_cmd = "rundll32.exe powrprof.dll,SetSuspendState 0,1,0"
        
        await self.update_status_message(user_id, chat_id, f"Sending sleep command to {device.name}...", context)
        
        success, output = await self.executor.ssh_command(device, sleep_cmd)
        
        if not success:
            await self.update_status_message(user_id, chat_id, f"Sleep failed for {device.name}\nError: {output}", context)
            return
        
        await self.update_status_message(user_id, chat_id, f"Sleep command sent to {device.name}\nWaiting for device to sleep...💤", context)
        
        max_attempts = 12
        for attempt in range(max_attempts):
            await asyncio.sleep(5)
            is_up = await self.executor.ping_device(device.ip)
            if not is_up:
                await self.update_status_message(user_id, chat_id, f"{device.name} is sleeping or down🛑", context)
                return
        
        await self.update_status_message(user_id, chat_id, f"{device.name} is still UP after 60 seconds\nCheck manually", context)
    
    async def _status_device(self, device: Device, user_id: int, chat_id: int, context: ContextTypes.DEFAULT_TYPE):
        await self.update_status_message(user_id, chat_id, f"Checking {device.name} status...", context)
        
        is_ping_up = await self.executor.ping_device(device.ip)
        
        if is_ping_up:
            await self.update_status_message(user_id, chat_id, f"{device.name} is UP ✅ (responds to ping)", context)
        else:
            success, output = await self.executor.ssh_command(device, "echo 'SSH test'", timeout=5)
            
            if success:
                await self.update_status_message(user_id, chat_id, f"{device.name} is UP ✅(SSH accessible, ping blocked)", context)
            else:
                await self.update_status_message(user_id, chat_id, f"{device.name} is DOWN 🛑 \nNo response to ping or SSH", context)
    
    def create_device_command_handler(self, action: str, device_name: str) -> Callable:
        async def handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            user_id = update.effective_user.id
            if not self.is_authorized(user_id):
                return await self.send_unauthorized(update)
            
            chat_id = update.message.chat_id
            await self._execute_device_action(action, device_name, user_id, chat_id, context)
            await self.delete_message_safe(chat_id, update.message.message_id, context)
        
        return handler
    
    def run(self):
        try:
            self.config.load_config()
            print(f"Loaded {len(self.config.devices)} devices")
            print(f"Authorized user IDs: {', '.join(map(str, self.config.authorized_user_ids))}")
        except Exception as e:
            print(f"Configuration error: {e}")
            sys.exit(1)
        
        app = ApplicationBuilder().token(self.config.token).build()
        
        app.add_handler(CommandHandler("start", self.start_command))
        app.add_handler(CommandHandler("help", self.help_command))
        app.add_handler(CommandHandler("menu", self.menu_command))
        app.add_handler(CommandHandler("list", self.list_command))
        
        add_device_handler = ConversationHandler(
            entry_points=[
                CommandHandler("add_device", self.add_device_start),
                CallbackQueryHandler(self.add_device_start, pattern="^add_device$")
            ],
            states={
                ADD_NAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_name)],
                ADD_IP: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_ip)],
                ADD_MAC: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_mac)],
                ADD_OS: [CallbackQueryHandler(self.add_device_os, pattern="^os:")],
                ADD_USER: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_user)],
                ADD_PORT: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_port),
                    CommandHandler("skip", self.add_device_skip_port)
                ],
                ADD_SSH_KEY: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.add_device_ssh_key),
                    CommandHandler("skip", self.add_device_skip_ssh_key)
                ],
            },
            fallbacks=[CommandHandler("cancel", self.add_device_cancel)],
        )
        app.add_handler(add_device_handler)
        
        app.add_handler(CallbackQueryHandler(self.button_callback))
        
        for device_name in self.config.devices:
            for action in ["wake", "shutdown", "restart", "status"]:
                command_name = f"{action}_{self.format_device_key(device_name)}"
                handler = self.create_device_command_handler(action, device_name)
                app.add_handler(CommandHandler(command_name, handler))
            
            device = self.config.devices[device_name]
            if device.os.lower() == 'windows':
                command_name = f"sleep_{self.format_device_key(device_name)}"
                handler = self.create_device_command_handler("sleep", device_name)
                app.add_handler(CommandHandler(command_name, handler))
        
        print("Starting Telegram Device Management Bot...")
        print("Bot is ready!")
        app.run_polling()

def main():
    try:
        bot = DeviceBot()
        bot.run()
    except KeyboardInterrupt:
        print("\nBot stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()