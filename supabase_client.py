import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

url: str = os.environ.get("SUPABASE_URL")
# IMPORTANT: Use the SERVICE_ROLE key to be able to write data (like the token)
key: str = os.environ.get("SUPABASE_KEY")

supabase: Client = create_client(url, key)

def get_user_by_username(username: str) -> dict | None:
    """Fetches a single user from the 'users' table by their username."""
    try:
        response = supabase.table('users').select("*").eq('username', username).single().execute()
        return response.data
    except Exception as e:
        # Using single() will raise an error if no user is found, which is fine.
        # We can log this for debugging but return None to the caller.
        # print(f"Info: User '{username}' not found in Supabase. {e}")
        return None

# --- NEW FUNCTIONS START ---

def get_config_file(name: str) -> dict | None:
    """
    Fetches a configuration file (like token.json) from the 'config_files' table.
    
    Args:
        name: The name of the file to fetch (e.g., 'token.json').
        
    Returns:
        A dictionary with the file's JSON content, or None if not found.
    """
    try:
        response = supabase.table('config_files').select("content").eq('name', name).single().execute()
        # The content is nested inside the 'content' key
        return response.data.get('content') if response.data else None
    except Exception as e:
        # print(f"Info: Config file '{name}' not found in Supabase. {e}")
        return None

def save_config_file(name: str, content: dict):
    """
    Saves or updates a configuration file in the 'config_files' table.
    Uses upsert to either create the entry if it doesn't exist or update it if it does.
    
    Args:
        name: The name of the file to save (e.g., 'token.json').
        content: A dictionary containing the JSON data to save.
    """
    try:
        supabase.table('config_files').upsert({
            "name": name,
            "content": content
        }).execute()
        print(f"Successfully saved '{name}' to Supabase.")
    except Exception as e:
        print(f"Error saving '{name}' to Supabase: {e}")

# --- NEW FUNCTIONS END ---