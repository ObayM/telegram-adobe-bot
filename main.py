import os
import json
import base64
from email import message_from_bytes
from datetime import datetime, timedelta, timezone

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
# --- MODIFIED: We use from_client_secrets_file now as well

from telegram.constants import ParseMode
from google_auth_oauthlib.flow import InstalledAppFlow
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
from bs4 import BeautifulSoup

# --- MODIFIED: Removed the unused supabase config functions ---
from supabase_client import get_user_by_username

# --- CONFIGURATION ---
from dotenv import load_dotenv
load_dotenv()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") 
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
LOG_CHAT_ID = -1003081448550

# --- CONVERSATION STATES ---
GET_USERNAME, GET_PASSWORD, AUTHENTICATED = range(3)
# --- END CONFIGURATION ---

def format_time_ago(dt_object: datetime) -> str:
    """
    Takes a timezone-aware datetime object and returns a string like
    '5 minutes ago', '2 hours ago', '3 days ago', etc.
    """
    now = datetime.now(timezone.utc)
    delta = now - dt_object
    seconds = int(delta.total_seconds())

    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''} ago"
    
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    
    hours = minutes // 60
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    
    days = hours // 24
    if days < 7:
        return f"{days} day{'s' if days != 1 else ''} ago"
    
    weeks = days // 7
    if weeks < 5: # Roughly a month
        return f"{weeks} week{'s' if weeks != 1 else ''} ago"
        
    months = days // 30
    if months < 12:
        return f"{months} month{'s' if months != 1 else ''} ago"

    years = days // 365
    return f"{years} year{'s' if years != 1 else ''} ago"


# --- COMPLETELY REWRITTEN FUNCTION ---
def get_gmail_service():
    """
    Authenticates with the Gmail API using local file system credentials.
    - It tries to load 'token.json' from the local directory.
    - If not found or invalid, it uses 'credentials.json' to run a local
      authentication flow, generating a new 'token.json'.
    - It saves the new or refreshed token back to 'token.json'.
    """
    creds = None
    
    # 1. Check if token.json exists and load credentials from it.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    # 2. If there are no valid credentials, run the authentication flow.
    if not creds or not creds.valid:
        # If the token is expired and there's a refresh token, refresh it.
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        # Otherwise, start a new authentication flow.
        else:
            # Ensure the credentials.json file exists.
            if not os.path.exists('credentials.json'):
                print("FATAL ERROR: 'credentials.json' not found in the local directory.")
                print("Please download it from Google Cloud Console and place it here.")
                return None
            
            # Run the flow using the credentials.json file.
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # 3. Save the new or refreshed credentials to token.json.
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)
# --- END REWRITTEN FUNCTION ---


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Starts the conversation and asks for a username."""
    context.user_data.clear()
    await update.message.reply_text(
        "Welcome! To access your emails, please log in.\n\n"
        "Please enter your username:"
    )
    return GET_USERNAME


async def get_username(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Stores the username and asks for the password."""
    context.user_data['username'] = update.message.text
    await update.message.reply_text("Thank you. Now, please enter your password:")
    return GET_PASSWORD


async def get_password(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Checks credentials against Supabase and authenticates the user."""
    username = context.user_data.get('username')
    password = update.message.text
    
    user_data = get_user_by_username(username)
    
    if user_data and user_data.get('password') == password:
        await update.message.reply_text(
            "Login successful! You can now send me an email address to search for."
        )
        context.user_data['authenticated'] = True
        return AUTHENTICATED
    else:
        await update.message.reply_text(
            "Invalid username or password. Please type /start to try again."
        )
        context.user_data.clear()
        return ConversationHandler.END
    
def escape_markdown_v2(text: str) -> str:
    """Escapes characters for Telegram's MarkdownV2 parse mode."""
    escape_chars = r'_*[]()~`>#+-=|{}.!'
    return text.translate(str.maketrans({char: '\\' + char for char in escape_chars}))

async def handle_email_request(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handles email fetching for an authenticated user."""
    if not context.user_data.get('authenticated'):
        await update.message.reply_text("You are not logged in. Please type /start to log in.")
        return

    email_address = update.message.text
    await update.message.reply_text(f"Searching for the latest email from: {email_address}...")

    try:
        service = get_gmail_service()
        if not service:
            await update.message.reply_text("Could not connect to Gmail. Please check the server logs.")
            return
        
        results = service.users().messages().list(userId='me', q=f"to:{email_address}", maxResults=1).execute()
        messages = results.get('messages', [])

        if not messages:
            await update.message.reply_text("No emails found from that address.")
            return

        msg_id = messages[0]['id']
        
        message_data = service.users().messages().get(
            userId='me', 
            id=msg_id, 
            format='raw', 
            fields='raw,internalDate'
        ).execute()
        
        timestamp_ms = int(message_data['internalDate'])
        dt_object = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        
        formatted_date = dt_object.strftime("%A, %B %d, %Y at %I:%M %p")
        time_ago_str = format_time_ago(dt_object)
        
        raw_email = base64.urlsafe_b64decode(message_data['raw'].encode('ASCII'))
        email_message = message_from_bytes(raw_email)

        subject = email_message['subject']
        body = ""
        html_body = ""

        if email_message.is_multipart():
            for part in email_message.walk():
                if "attachment" in str(part.get("Content-Disposition")): continue
                if "text/plain" in part.get_content_type():
                    body = part.get_payload(decode=True).decode()
                    break
                elif "text/html" in part.get_content_type():
                    html_body = part.get_payload(decode=True).decode()
        else:
            if "text/plain" in email_message.get_content_type():
                body = email_message.get_payload(decode=True).decode()
            elif "text/html" in email_message.get_content_type():
                html_body = email_message.get_payload(decode=True).decode()
        
        if not body and html_body:
            soup = BeautifulSoup(html_body, "html.parser")
            body = soup.get_text(separator='\n', strip=True)

        escaped_date = escape_markdown_v2(formatted_date)
        escaped_time_ago = escape_markdown_v2(time_ago_str)
        escaped_email = escape_markdown_v2(email_address)
        escaped_subject = escape_markdown_v2(subject)
        escaped_body = escape_markdown_v2(body or '[No readable content found]')

        separator = r'-----------------------------------'.replace('-', r'\-')

        response_text = (
            f"📧 *Latest Email from:* {escaped_email}\n\n"
            f"🗓️ *Date:* {escaped_date}\n"
            f"⏳ *Received:* {escaped_time_ago}\n"
            f"*Subject:* {escaped_subject}\n\n"
            f"{separator}\n\n"
            f"{escaped_body}"
        )

        if len(response_text) > 4096:
            response_text = response_text[:4090] + "\n\n\\[Message Truncated\\]"
        
        # Send the formatted email to the user
        await update.message.reply_text(response_text, parse_mode=ParseMode.MARKDOWN_V2)
        
        # --- MODIFIED LOGGING BLOCK ---
        if LOG_CHAT_ID:
            # 1. Send the initial log message about the user action
            escaped_username = escape_markdown_v2(context.user_data.get('username'))
            log_message = (
                f"✅ *Log: Successful Request*\n\n"
                f"👤 *Bot User:* `{escaped_username}`\n"
                f"✉️ *Searched Email:* `{escaped_email}`"
            )
            await context.bot.send_message(
                chat_id=LOG_CHAT_ID, 
                text=log_message,
                parse_mode=ParseMode.MARKDOWN_V2
            )
            
            # 2. Send the full email content to the log channel as well
            await context.bot.send_message(
                chat_id=LOG_CHAT_ID,
                text=response_text, # Send the same message the user received
                parse_mode=ParseMode.MARKDOWN_V2
            )

    except HttpError as error:
        await update.message.reply_text(f'An API error occurred: {error}')
    except Exception as e:
        await update.message.reply_text(f'An unexpected error occurred: {e}')

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancels and ends the conversation."""
    await update.message.reply_text("Login process cancelled. Type /start to begin again.")
    context.user_data.clear()
    return ConversationHandler.END


def main() -> None:
    """Sets up the bot and starts polling."""
    if not TELEGRAM_BOT_TOKEN:
        print("Error: TELEGRAM_BOT_TOKEN not found in environment variables.")
        return
        
    print("Bot is starting...")
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler('start', start)],
        states={
            GET_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_username)],
            GET_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_password)],
            AUTHENTICATED: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email_request)],
        },
        fallbacks=[CommandHandler('cancel', cancel)],
    )

    application.add_handler(conv_handler)
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_email_request))

    application.run_polling()
    print("Bot has stopped.")


if __name__ == '__main__':
    main()