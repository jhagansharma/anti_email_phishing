import os
import json
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

def authenticate_user():
    """
    Authenticates the user with Google using OAuth 2.0 and returns the credentials.
    If a valid token exists in 'token.json', it will be reused. Otherwise, the user
    will be prompted to authenticate via a browser.
    """
    creds = None
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

    try:
        # Check if 'token.json' exists to load existing credentials
        token_path = os.path.join(os.path.dirname(__file__), "token.json")
        if os.path.exists(token_path):
            with open(token_path, 'r') as token:
                creds = Credentials.from_authorized_user_info(json.load(token), SCOPES)

        # If no valid credentials are available, prompt the user to authenticate
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)

            # Save the credentials to 'token.json' for future use
            with open(token_path, 'w') as token:
                token.write(creds.to_json())

    except FileNotFoundError as e:
        print("Error: 'credentials.json' file not found. Please ensure it exists in the project directory.")
        raise e
    except Exception as e:
        print(f"An unexpected error occurred during authentication: {e}")
        raise e

    return creds