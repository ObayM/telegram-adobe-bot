import os
import json # <-- Import json for parsing
import base64
from email import message_from_bytes

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
# --- MODIFIED: We use from_client_config instead of from_client_secrets_file
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

# --- MODIFIED: Import the new supabase client functions ---
from supabase_client import get_user_by_username, get_config_file, save_config_file

# --- CONFIGURATION ---
from dotenv import load_dotenv
load_dotenv()
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN") 
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
LOG_CHAT_ID = -4867116295

# --- CONVERSATION STATES ---
GET_USERNAME, GET_PASSWORD, AUTHENTICATED = range(3)
# --- END CONFIGURATION ---


# --- COMPLETELY REWRITTEN FUNCTION ---
def get_gmail_service():
    """
    Authenticates with the Gmail API using credentials stored in Supabase.
    - Fetches 'token.json' from Supabase.
    - If not found or invalid, it fetches 'credentials.json' from Supabase.
    - It runs the local auth flow to generate a new token.
    - It saves the new/refreshed 'token.json' back to Supabase.
    """
    creds = None
    
    # 1. Try to load token from Supabase
    token_info = get_config_file('token.json')
    if token_info:
        # Create credentials object from the dictionary fetched from Supabase
        creds = Credentials.from_authorized_user_info(token_info, SCOPES)

    # 2. If no valid credentials, run the auth flow
    if not creds or not creds.valid:
        # If token is expired, refresh it
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        # Otherwise, run the full authentication flow
        else:
            # Fetch credentials.json from Supabase
            client_secrets_info = get_config_file('credentials.json')
            if not client_secrets_info:
                print("FATAL ERROR: 'credentials.json' not found in Supabase.")
                print("Please upload it manually to the 'config_files' table.")
                return None
            
            # Run flow using the dictionary, not a file path
            flow = InstalledAppFlow.from_client_config(client_secrets_info, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # 3. Save the new/refreshed token back to Supabase
        # creds.to_json() returns a string, but our DB expects a dict (jsonb)
        # So we parse the string back into a dictionary before saving
        save_config_file('token.json', json.loads(creds.to_json()))
            
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
        message_data = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
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

        response_text = (
            f"📧 *Latest Email from:* {email_address}\n\n"
            f"*Subject:* {subject}\n\n"
            f"-----------------------------------\n\n"
            f"{body or '[No readable content found]'}"
        )

        if len(response_text) > 4096:
            response_text = response_text[:4090] + "\n\n[Message Truncated]"
        await update.message.reply_text(response_text, parse_mode='Markdown')
        
        if LOG_CHAT_ID:
            log_message = (
                f"✅ **Log: Successful Request**\n\n"
                f"👤 **Bot User:** `{context.user_data.get('username')}`\n"
                f"✉️ **Searched Email:** `{email_address}`"
            )
            await context.bot.send_message(
                chat_id=LOG_CHAT_ID, 
                text=log_message,
                parse_mode='Markdown'
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