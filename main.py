import os
import json
import base64
import logging
from email import message_from_bytes
from datetime import datetime, timezone

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    ConversationHandler,
)
from telegram.constants import ParseMode
from telegram.error import BadRequest # Import the specific error
from bs4 import BeautifulSoup
from dotenv import load_dotenv

from supabase_client import get_user_by_username

# --- CONFIGURATION ---
load_dotenv()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
LOG_CHAT_ID = os.environ.get("LOG_CHAT_ID") 
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GET_USERNAME, GET_PASSWORD, AUTHENTICATED = range(3)

# --- SETUP LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- REFACTORED HELPER FUNCTIONS ---

def format_time_ago(dt_object: datetime) -> str:
    now = datetime.now(timezone.utc)
    delta = now - dt_object
    seconds = int(delta.total_seconds())
    if seconds < 5: return "just now"
    time_units = [
        ('year', 31536000), ('month', 2592000), ('week', 604800),
        ('day', 86400), ('hour', 3600), ('minute', 60), ('second', 1)
    ]
    for unit, seconds_in_unit in time_units:
        if seconds >= seconds_in_unit:
            value = seconds // seconds_in_unit
            return f"{value} {unit}{'s' if value != 1 else ''} ago"
    return "just now"

def get_gmail_service():
    creds = None
    if not os.path.exists('token.json'):
        logger.critical("FATAL ERROR: 'token.json' not found. Generate it with generate_token.py.")
        return None
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
            logger.info("Credentials refreshed.")
        except Exception as e:
            logger.error(f"Failed to refresh credentials: {e}")
            return None
    return build('gmail', 'v1', credentials=creds)

def parse_email_body(email_message):
    body, html_body = "", ""
    if email_message.is_multipart():
        for part in email_message.walk():
            if "attachment" in str(part.get("Content-Disposition")): continue
            if part.get_content_type() == "text/plain" and not body:
                body = part.get_payload(decode=True).decode(errors='ignore')
            elif part.get_content_type() == "text/html":
                html_body = part.get_payload(decode=True).decode(errors='ignore')
    else:
        if "text/plain" in email_message.get_content_type():
            body = email_message.get_payload(decode=True).decode(errors='ignore')
        elif "text/html" in email_message.get_content_type():
            html_body = email_message.get_payload(decode=True).decode(errors='ignore')
    if not body and html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        body = soup.get_text(separator='\n', strip=True)
    return body or '[No readable content found]'

def escape_markdown_v2(text: str) -> str:
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return str(text).translate(str.maketrans({char: '\\' + char for char in escape_chars}))

# --- NEW ROBUST SENDING FUNCTION ---
async def send_robust_message(context: ContextTypes.DEFAULT_TYPE, chat_id: int, text: str):
    """
    Sends a message with MarkdownV2, falling back to plain text if parsing fails.
    This prevents the bot from crashing due to formatting errors.
    """
    try:
        await context.bot.send_message(
            chat_id=chat_id,
            text=text,
            parse_mode=ParseMode.MARKDOWN_V2
        )
    except BadRequest as e:
        if "Can't parse entities" in str(e):
            logger.warning(f"Markdown parsing failed: {e}. Sending as plain text.")
            # Send again without any formatting
            await context.bot.send_message(chat_id=chat_id, text=text)
        else:
            # Re-raise other types of BadRequest errors
            raise e

# --- TELEGRAM HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.clear()
    await update.message.reply_text("Welcome! Please enter your username:")
    return GET_USERNAME

async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data['username'] = update.message.text
    await update.message.reply_text("Password:")
    return GET_PASSWORD

async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    username = context.user_data.get('username')
    password = update.message.text
    user_data = get_user_by_username(username)
    if user_data and user_data.get('password') == password:
        await update.message.reply_text("Login successful! Send an email address to search for.")
        context.user_data['authenticated'] = True
        return AUTHENTICATED
    else:
        await update.message.reply_text("Invalid credentials. Use /start to try again.")
        context.user_data.clear()
        return ConversationHandler.END

async def handle_email_request(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not context.user_data.get('authenticated'):
        await update.message.reply_text("You are not logged in. Please use /start.")
        return

    email_address = update.message.text
    await update.message.reply_text(f"Searching for the latest email sent TO: {email_address}...")

    try:
        service = get_gmail_service()
        if not service:
            await update.message.reply_text("Error: Could not connect to Gmail. Please inform the admin.")
            return
        
        results = service.users().messages().list(userId='me', q=f"to:{email_address}", maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages:
            await update.message.reply_text(f"No emails found sent to '{email_address}'.")
            return

        msg_id = messages[0]['id']
        message_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        
        timestamp_ms = int(message_data['internalDate'])
        dt_object = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        
        raw_email = base64.urlsafe_b64decode(message_data['raw'].encode('ASCII'))
        email_message = message_from_bytes(raw_email)
        
        body = parse_email_body(email_message)
        subject = email_message.get('subject', 'No Subject')
        sender = email_message.get('from', 'Unknown Sender')

        # --- Build Response ---
        escaped_sender = escape_markdown_v2(sender)
        escaped_date = escape_markdown_v2(dt_object.strftime("%A, %d %B %Y at %H:%M %Z"))
        escaped_time_ago = escape_markdown_v2(format_time_ago(dt_object))
        escaped_subject = escape_markdown_v2(subject)
        escaped_body = escape_markdown_v2(body)
        separator = escape_markdown_v2('-----------------------------------')

        # **THE FIX IS HERE**: The parentheses are now escaped with backslashes
        response_text = (
            f"📨 *From:* {escaped_sender}\n"
            f"🗓️ *Date:* {escaped_date} \\({escaped_time_ago}\\)\n"
            f"📝 *Subject:* {escaped_subject}\n"
            f"{separator}\n\n"
            f"{escaped_body}"
        )

        if len(response_text) > 4096:
            response_text = response_text[:4090] + "\n\n\\[Message Truncated\\]"
        
        # Use the new robust sending function
        await send_robust_message(context, update.message.chat_id, response_text)
        
        if LOG_CHAT_ID:
            escaped_username = escape_markdown_v2(context.user_data.get('username'))
            log_message = (
                f"✅ *Log: Request by `{escaped_username}`*\n"
                f"✉️ *Searched for emails to:* `{escape_markdown_v2(email_address)}`\n"
                f"📬 *Found Email From:* {escaped_sender}"
            )
            # Use the robust function for logging as well
            await send_robust_message(context, LOG_CHAT_ID, log_message)
            await send_robust_message(context, LOG_CHAT_ID, response_text)

    except HttpError as error:
        logger.error(f"HttpError: {error}")
        await update.message.reply_text('An API error occurred. Please try again later.')
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        await update.message.reply_text('An unexpected error occurred. Please contact the admin.')

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    await update.message.reply_text("Login cancelled. Type /start to begin again.")
    context.user_data.clear()
    return ConversationHandler.END

def main() -> None:
    if not TELEGRAM_BOT_TOKEN:
        logger.critical("Error: TELEGRAM_BOT_TOKEN not found in environment variables.")
        return
        
    logger.info("Bot is starting...")
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            GET_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            GET_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            AUTHENTICATED: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email_request)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
        per_message=False
    )
    application.add_handler(conv_handler)
    application.run_polling()
    logger.info("Bot has stopped.")

if __name__ == '__main__':
    main()